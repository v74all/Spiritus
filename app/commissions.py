"""Multi-level reseller commissions and wallet ledger.

Differential model: the reseller who owns the sale earns their own
``commission_rate``; each ancestor earns only the *margin* by which their rate
exceeds the highest rate already paid below them. Total payout therefore never
exceeds the top-most reseller's rate.
"""

from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Payment, Reseller, ResellerLedger


class InsufficientBalanceError(Exception):
    pass


MAX_TREE_DEPTH = 3  # reseller -> sub-reseller -> sub-sub-reseller


async def ancestors(db: AsyncSession, reseller: Reseller) -> list[Reseller]:
    """Chain from ``reseller`` (inclusive) up to the root, cycle-safe."""
    chain: list[Reseller] = [reseller]
    seen = {reseller.id}
    current = reseller
    while current.parent_id is not None and len(chain) <= MAX_TREE_DEPTH + 1:
        if current.parent_id in seen:
            break
        parent = (
            await db.execute(select(Reseller).where(Reseller.id == current.parent_id))
        ).scalar_one_or_none()
        if parent is None:
            break
        chain.append(parent)
        seen.add(parent.id)
        current = parent
    return chain


async def post_ledger_entry(
    db: AsyncSession,
    reseller_id: int,
    amount: int,
    kind: str,
    *,
    payment_id: int | None = None,
    note: str | None = None,
    allow_negative: bool = True,
) -> ResellerLedger:
    """Atomically change the balance and append the matching ledger row (no commit).

    With ``allow_negative=False`` the debit is applied only if it leaves a
    non-negative balance (checked inside the UPDATE, so concurrent debits can't overdraw).
    """
    stmt = update(Reseller).where(Reseller.id == reseller_id)
    if not allow_negative:
        stmt = stmt.where(Reseller.balance + amount >= 0)
    result = await db.execute(stmt.values(balance=Reseller.balance + amount))
    if result.rowcount == 0:
        raise InsufficientBalanceError(reseller_id)
    balance_after = (
        await db.execute(select(Reseller.balance).where(Reseller.id == reseller_id))
    ).scalar_one()
    entry = ResellerLedger(
        reseller_id=reseller_id,
        payment_id=payment_id,
        kind=kind,
        amount=amount,
        balance_after=int(balance_after or 0),
        note=note,
    )
    db.add(entry)
    await db.flush()
    return entry


async def credit_commissions(db: AsyncSession, payment: Payment) -> list[ResellerLedger]:
    """Credit the seller and every ancestor for a paid payment. Caller commits."""
    if not payment.reseller_id or not payment.amount:
        return []
    seller = (
        await db.execute(select(Reseller).where(Reseller.id == payment.reseller_id))
    ).scalar_one_or_none()
    if seller is None:
        return []

    entries: list[ResellerLedger] = []
    paid_rate = 0.0
    for index, node in enumerate(await ancestors(db, seller)):
        rate = float(node.commission_rate or 0)
        margin = rate - paid_rate
        if margin <= 0:
            continue
        paid_rate = rate
        amount = int(payment.amount * margin / 100)
        if amount <= 0:
            continue
        entries.append(
            await post_ledger_entry(
                db,
                node.id,
                amount,
                "commission" if index == 0 else "override",
                payment_id=payment.id,
                note=f"{margin:g}% of payment {payment.id}",
            )
        )
    return entries
