(function () {
  'use strict';

  var EVENT_ATTRS = [
    'onclick',
    'onchange',
    'oninput',
    'onkeydown',
    'onkeypress',
    'onmouseover',
    'onmouseout'
  ];

  var ALLOWED_CALLS = new Set([
    'applyFilter',
    'autoSelectBestSNI',
    'cleanupBackups',
    'closeActivity',
    'closeDrawer',
    'closeModal',
    'copyAgentAppLink',
    'copyAppProfile',
    'copyBulkOutput',
    'copyConfigLink',
    'copyLink',
    'copySubUrl',
    'createBackup',
    'deleteAgent',
    'deleteBackup',
    'deleteBulkGroup',
    'deleteGroup',
    'deleteUser',
    'doAddAgent',
    'doAddTraffic',
    'doAddUser',
    'doBulkCreate',
    'doChangePw',
    'doEditAgentQuota',
    'doExportCSV',
    'doExportJSON',
    'doLogin',
    'doLogout',
    'doRenewUser',
    'doResetAgentPw',
    'doSearch',
    'doToggle',
    'domainCheckOptions',
    'domainDisable',
    'domainRenew',
    'domainSet',
    'downloadBulkCSV',
    'downloadBulkZip',
    'fetchFirewallStats',
    'fetchOnlineUsers',
    'forceSync',
    'generateSS2022Key',
    'hideModal',
    'loadAnalytics',
    'loadBackups',
    'openAppModal',
    'openBulkInNewTab',
    'openGroupExport',
    'openGroupUsers',
    'promptEditNote',
    'promptSpeed',
    'regenerateReality',
    'resetSettingsToDefault',
    'restoreBackup',
    'runFirewallAttack',
    'saveBrand',
    'saveSettings',
    'selectBulkRun',
    'setTarget',
    'showActivity',
    'showAddTraffic',
    'showConfig',
    'showEditAgent',
    'showModal',
    'showQr',
    'showRenew',
    'showResetAgentPw',
    'showUserIPs',
    'startAggressiveAttack',
    'startCounter',
    'startFightBack',
    'startResilienceOp',
    'stopAggressiveAttack',
    'stopFightBack',
    'stopFirewallAttacks',
    'stopResilienceOps',
    'switchActivityTab',
    'switchAggressiveTab',
    'switchConfigTab',
    'switchFightbackTab',
    'switchMainView',
    'switchSettingsTab',
    'testTelegram',
    'toggleAgent',
    'toggleAgentAppLink',
    'toggleCDN',
    'toggleDirection',
    'toggleDrawer',
    'toggleKillSwitch',
    'toggleUser',
    'verifyIranianTarget',
    'verifyNetworkTarget',
    'withBusy'
  ]);

  function splitTopLevel(value, separator) {
    var out = [];
    var start = 0;
    var quote = '';
    var depth = 0;
    for (var i = 0; i < value.length; i += 1) {
      var ch = value[i];
      if (quote) {
        if (ch === '\\') {
          i += 1;
        } else if (ch === quote) {
          quote = '';
        }
        continue;
      }
      if (ch === '\'' || ch === '"') {
        quote = ch;
      } else if (ch === '(') {
        depth += 1;
      } else if (ch === ')') {
        depth = Math.max(0, depth - 1);
      } else if (ch === separator && depth === 0) {
        out.push(value.slice(start, i).trim());
        start = i + 1;
      }
    }
    var tail = value.slice(start).trim();
    if (tail) out.push(tail);
    return out;
  }

  function stripQuotes(value) {
    value = value.trim();
    if ((value[0] === '\'' && value[value.length - 1] === '\'') ||
        (value[0] === '"' && value[value.length - 1] === '"')) {
      return value.slice(1, -1).replace(/\\(['"\\])/g, '$1');
    }
    return null;
  }

  function parseArg(raw, element, event) {
    var value = raw.trim();
    var quoted = stripQuotes(value);
    if (quoted !== null) return quoted;
    if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
    if (value === 'true') return true;
    if (value === 'false') return false;
    if (value === 'null') return null;
    if (value === 'event') return event;
    if (value === 'this') return element;
    if (value === 'this.id') return element.id;
    if (value === 'this.value') return element.value;
    if (value === 'event.target') return event.target;
    if (value === 'event.currentTarget') return event.currentTarget;
    return undefined;
  }

  function parseArgs(raw, element, event) {
    if (!raw.trim()) return [];
    return splitTopLevel(raw, ',').map(function (arg) {
      return parseArg(arg, element, event);
    });
  }

  function checkCondition(raw, element, event) {
    var value = raw.trim();
    if (value === 'event.target===this' || value === 'event.target === this') {
      return event.target === element;
    }
    var enterMatch = value.match(/^event\.key\s*===\s*(['"])Enter\1$/);
    if (enterMatch) return event.key === 'Enter';
    return false;
  }

  function assignStyle(statement, element) {
    var parentMatch = statement.match(/^this\.parentElement\.style\.([A-Za-z$][\w$]*)\s*=\s*(['"])(.*?)\2$/);
    if (parentMatch && element.parentElement) {
      element.parentElement.style[parentMatch[1]] = parentMatch[3];
      return true;
    }
    var styleMatch = statement.match(/^this\.style\.([A-Za-z$][\w$]*)\s*=\s*(['"])(.*?)\2$/);
    if (styleMatch) {
      element.style[styleMatch[1]] = styleMatch[3];
      return true;
    }
    return false;
  }

  function assignText(statement, element) {
    var match = statement.match(/^document\.getElementById\((['"])(.*?)\1\)\.textContent\s*=\s*this\.value\s*\|\|\s*(['"])(.*?)\3$/);
    if (!match) return false;
    var target = document.getElementById(match[2]);
    if (target) target.textContent = element.value || match[4];
    return true;
  }

  function runStatement(statement, element, event) {
    if (!statement) return;

    var ifMatch = statement.match(/^if\s*\((.*)\)\s*(.+)$/);
    if (ifMatch) {
      if (checkCondition(ifMatch[1], element, event)) {
        runHandler(ifMatch[2], element, event);
      }
      return;
    }

    if (statement === 'event.stopPropagation()') {
      event.stopPropagation();
      return;
    }

    if (assignStyle(statement, element) || assignText(statement, element)) {
      return;
    }

    var callMatch = statement.match(/^([A-Za-z_$][\w$]*)\s*\(([\s\S]*)\)$/);
    if (!callMatch) return;
    var name = callMatch[1];
    if (!ALLOWED_CALLS.has(name) || typeof window[name] !== 'function') return;
    window[name].apply(element, parseArgs(callMatch[2], element, event));
  }

  function runHandler(source, element, event) {
    splitTopLevel(source, ';').forEach(function (statement) {
      runStatement(statement, element, event);
    });
  }

  function bindElement(element) {
    if (element.hasAttribute && element.hasAttribute('style')) {
      var styleText = element.getAttribute('style') || '';
      element.removeAttribute('style');
      if (styleText) element.style.cssText = styleText;
    }

    EVENT_ATTRS.forEach(function (attr) {
      if (!element.hasAttribute || !element.hasAttribute(attr)) return;
      var source = element.getAttribute(attr) || '';
      element.removeAttribute(attr);
      var type = attr.slice(2);
      element.addEventListener(type, function (event) {
        runHandler(source, element, event);
      });
    });
  }

  function bindTree(root) {
    if (!root || !root.querySelectorAll) return;
    if (root.nodeType === 1) bindElement(root);
    var selector = EVENT_ATTRS.map(function (attr) { return '[' + attr + ']'; }).join(',');
    root.querySelectorAll(selector).forEach(bindElement);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { bindTree(document); });
  } else {
    bindTree(document);
  }

  new MutationObserver(function (mutations) {
    mutations.forEach(function (mutation) {
      mutation.addedNodes.forEach(bindTree);
    });
  }).observe(document.documentElement, { childList: true, subtree: true });
}());
