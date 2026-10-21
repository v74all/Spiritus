"""Every in-page view must sit inside the main content column.

A stray closing tag in the settings markup once closed <main> early: the
Agents, Online and Backup views then rendered below the screen (blank page)
while every element-level check still passed."""

from html.parser import HTMLParser
from pathlib import Path

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


class Nesting(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack: list[tuple[str, str]] = []
        self.views: dict[str, bool] = {}
        self.errors: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in VOID:
            return
        a = dict(attrs)
        cls = a.get("class") or ""
        if "tactical-op-view" in cls.split():
            self.views[a.get("id", "?")] = any("ui-content" in c.split() for _, c in self.stack)
        self.stack.append((tag, cls))

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack or self.stack[-1][0] != tag:
            self.errors.append(f"line {self.getpos()[0]}: </{tag}> does not close <{self.stack[-1][0] if self.stack else '-'}>")
            return
        self.stack.pop()


def _parse(name):
    p = Nesting()
    p.feed((Path(__file__).resolve().parents[2] / "templates" / name).read_text(encoding="utf-8"))
    return p


def test_admin_views_are_all_inside_the_main_column():
    p = _parse("panel.html")
    assert len(p.views) >= 15
    assert [v for v, inside in p.views.items() if not inside] == []


def test_admin_and_agent_markup_is_balanced():
    for name in ("panel.html", "agent-panel.html"):
        assert _parse(name).errors[:3] == [], name
