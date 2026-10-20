/* Spiritus UI: dialogs as side sheets, and in-app replacements for the
   browser's confirm() / alert() / prompt() boxes. Shared by the admin and
   agent panels; styles live in ui.css.

   - Every .modal-overlay > .modal opens as a sheet docked to the inline-end
     edge (a bottom sheet on phones), with a pinned header + close button and
     a pinned action bar. Esc closes the top sheet; focus returns afterwards.
   - uiConfirm(message, {danger, confirmLabel})  -> Promise<boolean>
   - uiNotice(message, type)                     -> Promise<void> (one "OK")
   - uiForm({title, description, fields, submitLabel}) -> Promise<values|null>
*/
(function () {
  'use strict';

  var lastFocus = [];

  function close(overlay) {
    if (overlay._uiDone) { overlay._uiDone(null); return; }
    if (typeof window.closeModal === 'function') window.closeModal(overlay.id);
    else overlay.classList.remove('show');
  }

  function decorate(overlay) {
    var panel = overlay.querySelector(':scope > .modal');
    if (!panel || panel.dataset.sheet) return;
    panel.dataset.sheet = '1';
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');
    var first = panel.firstElementChild;
    var title = first && (first.matches('h3') ? first : first.querySelector(':scope > h3'));
    if (title) {
      first.classList.add('sheet-head');
      if (!title.id) title.id = (overlay.id || 'sheet') + '-title';
      panel.setAttribute('aria-labelledby', title.id);
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'ui-icon-btn sheet-close';
      btn.setAttribute('aria-label', 'Close');
      btn.title = 'Close (Esc)';
      btn.innerHTML = '<span class="material-symbols-outlined" aria-hidden="true">close</span>';
      btn.addEventListener('click', function () { close(overlay); });
      first.appendChild(btn);
    }
    var last = panel.lastElementChild;
    if (last && last.classList.contains('modal-actions')) last.classList.add('sheet-foot');
  }

  function openSheets() { return document.querySelectorAll('.modal-overlay.show'); }

  function syncOpenState() {
    document.documentElement.classList.toggle('sheet-open', openSheets().length > 0);
  }

  // Focus the first field when a sheet opens; give focus back when it closes.
  function watch(overlay) {
    decorate(overlay);
    new MutationObserver(function () {
      var shown = overlay.classList.contains('show');
      if (shown && !overlay._uiShown) {
        overlay._uiShown = true;
        lastFocus.push(document.activeElement);
        setTimeout(function () {
          var target = overlay.querySelector('.modal input:not([type=hidden]):not([readonly]), .modal select, .modal textarea:not([readonly])')
            || overlay.querySelector('.sheet-close');
          if (target) target.focus({ preventScroll: true });
        }, 60);
      } else if (!shown && overlay._uiShown) {
        overlay._uiShown = false;
        var prev = lastFocus.pop();
        if (prev && prev.focus && document.contains(prev)) prev.focus({ preventScroll: true });
      }
      syncOpenState();
    }).observe(overlay, { attributes: true, attributeFilter: ['class'] });
  }

  /* ── Confirm / notice bar ──────────────────────────────────── */
  var barResolve = null;

  function bar() {
    var el = document.getElementById('ui-confirm');
    if (el) return el;
    el = document.createElement('div');
    el.id = 'ui-confirm';
    el.className = 'ui-confirm';
    el.setAttribute('role', 'alertdialog');
    el.setAttribute('aria-live', 'assertive');
    el.innerHTML = '<span class="material-symbols-outlined ui-confirm-icon" aria-hidden="true">help</span>' +
      '<div class="ui-confirm-text"></div>' +
      '<div class="ui-confirm-actions">' +
      '<button type="button" class="btn btn-outline btn-sm" data-act="no">Cancel</button>' +
      '<button type="button" class="btn btn-primary btn-sm" data-act="yes">Confirm</button></div>';
    el.addEventListener('click', function (e) {
      var b = e.target.closest('[data-act]');
      if (b) settle(b.getAttribute('data-act') === 'yes');
    });
    document.body.appendChild(el);
    return el;
  }

  function settle(value) {
    var el = document.getElementById('ui-confirm');
    if (el) el.classList.remove('show');
    var resolve = barResolve;
    barResolve = null;
    if (resolve) resolve(value);
  }

  var DANGER = /delete|remove|purge|restore|reset|disable|disconnect|panic|حذف|بازنشانی/i;

  window.uiConfirm = function (message, opts) {
    opts = opts || {};
    if (barResolve) settle(false);
    var el = bar();
    var danger = opts.danger !== undefined ? !!opts.danger : DANGER.test(message);
    var yes = el.querySelector('[data-act="yes"]');
    var no = el.querySelector('[data-act="no"]');
    el.querySelector('.ui-confirm-text').textContent = String(message).replace(/\\n/g, '\n');
    el.querySelector('.ui-confirm-icon').textContent = opts.icon || (danger ? 'warning' : 'help');
    yes.className = 'btn btn-sm ' + (danger ? 'btn-danger' : 'btn-primary');
    yes.textContent = opts.confirmLabel || (danger ? 'Yes, continue' : 'Confirm');
    no.hidden = !!opts.noCancel;
    el.classList.toggle('is-danger', danger);
    el.classList.toggle('is-error', opts.tone === 'error');
    el.classList.toggle('is-ok', opts.tone === 'ok');
    el.classList.add('show');
    setTimeout(function () { (opts.noCancel ? yes : no).focus(); }, 40);
    return new Promise(function (resolve) { barResolve = resolve; });
  };

  window.uiNotice = function (message, type) {
    var tone = type === 'error' ? 'error' : (type === 'ok' ? 'ok' : '');
    return window.uiConfirm(message, {
      noCancel: true, danger: false, tone: tone, confirmLabel: 'OK',
      icon: tone === 'error' ? 'error' : (tone === 'ok' ? 'check_circle' : 'info')
    }).then(function () {});
  };

  /* ── Form sheet (replaces prompt) ──────────────────────────── */
  window.uiForm = function (opts) {
    return new Promise(function (resolve) {
      var overlay = document.createElement('div');
      overlay.className = 'modal-overlay';
      overlay.id = 'ui-form-sheet-' + Date.now();
      var panel = document.createElement('div');
      panel.className = 'modal';
      var head = document.createElement('h3');
      head.textContent = opts.title || '';
      panel.appendChild(head);
      if (opts.description) {
        var lead = document.createElement('p');
        lead.className = 'settings-desc ui-form-lead';
        lead.textContent = opts.description;
        panel.appendChild(lead);
      }
      var inputs = {};
      (opts.fields || []).forEach(function (f, i) {
        var group = document.createElement('div');
        group.className = 'form-group';
        var input = document.createElement(f.multiline ? 'textarea' : 'input');
        input.id = overlay.id + '-f' + i;
        if (!f.multiline) input.type = f.type || 'text';
        if (f.min !== undefined) input.min = f.min;
        if (f.maxlength) input.maxLength = f.maxlength;
        if (f.placeholder) input.placeholder = f.placeholder;
        input.value = f.value !== undefined && f.value !== null ? f.value : '';
        var label = document.createElement('label');
        label.htmlFor = input.id;
        label.textContent = f.label;
        group.appendChild(label);
        group.appendChild(input);
        if (f.hint) {
          var hint = document.createElement('div');
          hint.className = 'settings-desc';
          hint.textContent = f.hint;
          group.appendChild(hint);
        }
        panel.appendChild(group);
        inputs[f.name] = input;
      });
      var actions = document.createElement('div');
      actions.className = 'modal-actions';
      var ok = document.createElement('button');
      ok.type = 'button';
      ok.className = 'btn btn-primary';
      ok.textContent = opts.submitLabel || 'Save';
      var cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.className = 'btn btn-outline';
      cancel.textContent = 'Cancel';
      actions.appendChild(ok);
      actions.appendChild(cancel);
      panel.appendChild(actions);
      overlay.appendChild(panel);
      document.body.appendChild(overlay);

      var finished = false;
      function done(value) {
        if (finished) return;
        finished = true;
        overlay.classList.remove('show');
        setTimeout(function () { overlay.remove(); syncOpenState(); }, 200);
        resolve(value);
      }
      overlay._uiDone = done;
      ok.addEventListener('click', function () {
        var out = {};
        Object.keys(inputs).forEach(function (k) { out[k] = inputs[k].value; });
        done(out);
      });
      cancel.addEventListener('click', function () { done(null); });
      overlay.addEventListener('click', function (e) { if (e.target === overlay) done(null); });
      panel.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); ok.click(); }
      });
      watch(overlay);
      overlay.classList.add('show');
    });
  };

  /* ── Esc closes the confirm bar, else the top sheet ─────────── */
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    if (barResolve) { e.preventDefault(); settle(false); return; }
    var open = openSheets();
    if (open.length) { e.preventDefault(); close(open[open.length - 1]); }
  });

  function init() {
    document.querySelectorAll('.modal-overlay').forEach(watch);
    syncOpenState();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
