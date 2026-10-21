// ── CSRF / fetch hardening ──
// Auto-attach X-CSRF-Token to every unsafe same-origin request so the new
// CSRF middleware (app/middleware/csrf.py) accepts them. The token is read
// from the `csrf_token` cookie on every call, so rotation just works.
(function () {
  function readCookie(name) {
    const m = document.cookie.match('(?:^|; )' + name.replace(/[.$?*|{}()[\]\\/+^]/g, '\\$&') + '=([^;]*)');
    return m ? decodeURIComponent(m[1]) : '';
  }
  const SAFE = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
  const origFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    init = init || {};
    const method = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
    // Same-origin only — never leak the CSRF token to other origins.
    let urlStr = '';
    try { urlStr = (typeof input === 'string') ? input : (input && input.url) || ''; } catch (e) {}
    const sameOrigin = !urlStr || urlStr.startsWith('/') || urlStr.startsWith(location.origin);
    if (!SAFE.has(method) && sameOrigin) {
      const token = readCookie('csrf_token');
      if (token) {
        const headers = new Headers(init.headers || {});
        if (!headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', token);
        init.headers = headers;
      }
      if (!('credentials' in init)) init.credentials = 'same-origin';
    }
    return origFetch(input, init);
  };
})();

const API = '/api';
// QR_LIB_URL and SERVER_INFO are injected by the template in panel.html
let users = [];

// ── apiCall: standardised fetch wrapper used by action handlers ──
// Every action button used to do `const d = await (await fetch(...)).json()`
// with no status check. On 403 (CSRF rejected) or 500 the JSON body still
// parses, but `d.ok` is undefined, the if (d.ok) branch falls through, and
// the user sees a generic "Error" toast — or nothing at all when the call
// site swallowed the exception in `catch(e){}`. The result was the
// long-standing "buttons don't work" report.
//
// apiCall surfaces the actual status with a useful toast message and throws
// a sentinel so the call site's try/catch can stop without showing a
// duplicate error. On 401 it reloads (session expired). Success returns the
// parsed JSON body. On a network failure (no response at all) the error is
// surfaced and re-thrown.
async function apiCall(url, opts) {
  let r;
  try {
    r = await fetch(url, opts);
  } catch (e) {
    if (typeof toast === 'function') toast('Network error — check connection', 'error');
    throw e;
  }
  if (r.status === 401) { location.reload(); throw new Error('reauth'); }
  let body = null;
  try { body = await r.json(); } catch { body = {}; }
  if (!r.ok) {
    let detail = body && (body.detail || body.error);
    if (detail && typeof detail === 'object') detail = detail.error || detail.message || '';
    const msg = detail || ('HTTP ' + r.status);
    if (typeof toast === 'function') toast(msg, 'error');
    const err = new Error(msg);
    err.status = r.status;
    err.body = body;
    throw err;
  }
  return body;
}

// withBusy: disables a button for the lifetime of an async action so a
// double-click can't fire the underlying fetch twice. Use as:
//   onclick="withBusy(this, () => doToggle('u1'))"
// or inside JS:  withBusy(btn, async () => { ... })
async function withBusy(btn, fn) {
  if (btn && btn.disabled) return;
  const prev = btn ? btn.disabled : false;
  if (btn) btn.disabled = true;
  try {
    return await fn();
  } finally {
    if (btn) btn.disabled = prev;
  }
}

let prevLive = {}, prevTime = 0, speeds = {};
let renewTarget = '';
let polling = false;
let currentFilter = 'all';
let serverInfo = {};
let configTab = 'vmess';
let configTarget = null;
let mainView = 'users';
let groups = [];
let _settingsLoaded = false;
let _settingsLoading = null;
let _settingsCache = {};

function asBool(v) {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v !== 0;
  if (typeof v === 'string') return ['1', 'true', 'yes', 'on'].includes(v.trim().toLowerCase());
  return false;
}

function setVal(id, val) { const el = document.getElementById(id); if (el) el.value = val; }
function setChk(id, val) { const el = document.getElementById(id); if (el) el.checked = !!val; }

function setKillSwitchCheckboxes(on) {
  ['set-ks', 'set-security-ks'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.checked = !!on;
  });
}

function getKillSwitchValue() {
  const primary = document.getElementById('set-ks');
  const secondary = document.getElementById('set-security-ks');
  return !!((primary && primary.checked) || (secondary && secondary.checked));
}
// SERVER_INFO is injected by the template in panel.html

/* ── Auth ── */
async function doLogin() {
  const userEl = document.getElementById('login-user');
  const user = userEl ? userEl.value.trim() : 'admin';
  const pw = document.getElementById('login-pass').value;
  const totpEl = document.getElementById('login-totp');
  const totp = totpEl ? totpEl.value.trim() : '';
  const errEl = document.getElementById('login-error');
  const btn = document.getElementById('login-submit');
  if (!btn) return;
  errEl.textContent = '';
  if (!pw) {
    // An empty submit would still count as a failed attempt (and toward fail2ban).
    errEl.textContent = 'Enter your password';
    document.getElementById('login-pass').focus();
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Signing in...';
  try {
    const body = { username: user || 'admin', password: pw };
    if (totp) body.totp_code = totp;
    const r = await fetch(API + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'same-origin'
    });
    let d = {};
    try {
      d = await r.json();
    } catch (e) {
      errEl.textContent = 'Invalid server response';
      btn.disabled = false;
      btn.textContent = 'Authenticate';
      return;
    }
    if (r.ok && d.ok) {
      document.getElementById('login-screen').style.display = 'none';
      document.getElementById('panel').style.display = 'block';
      switchOperationTab('tenants');
      startPolling();
      btn.disabled = false;
      btn.textContent = 'Authenticate';
      return;
    }
    // Password accepted, second factor required: reveal the TOTP field and
    // let the operator submit again with the code.
    if (d.totp_required) {
      if (totpEl) {
        const field = document.getElementById('login-totp-field');
        if (field) field.hidden = false;
        totpEl.focus();
      }
      errEl.textContent = 'Enter your 2FA code';
      btn.disabled = false;
      btn.textContent = 'Authenticate';
      return;
    }
    errEl.textContent = d.error || 'Error';
    if (d.locked) {
      btn.disabled = true;
      btn.textContent = 'Locked';
      setTimeout(() => {
        btn.disabled = false;
        btn.textContent = 'Authenticate';
        errEl.textContent = '';
      }, 60000);
      return;
    }
    btn.disabled = false;
    btn.textContent = 'Authenticate';
    document.getElementById('login-pass').value = '';
    document.getElementById('login-pass').focus();
  } catch (e) {
    errEl.textContent = 'Connection error';
    btn.disabled = false;
    btn.textContent = 'Authenticate';
  }
}

async function toggleDirection() {
  var cur = document.documentElement.dir || 'ltr';
  var nxt = cur === 'rtl' ? 'ltr' : 'rtl';
  document.documentElement.dir = nxt;
  try {
    var r = await fetch('/api/direction', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({dir:nxt}), credentials:'same-origin'});
    if (r.ok) { setTimeout(function(){ location.reload(); }, 100); return; }
  } catch(e) {}
  location.reload();
}

async function doLogout() {
  await fetch(API+'/logout', {method:'POST'});
  location.reload();
}

/* ── Data ── */
async function fetchUsers() {
  try {
    const r = await fetch(API+'/users');
    if (r.status === 401) { location.reload(); return; }
    users = await r.json();
    if (mainView === 'users') renderUsers();
    updateStats();
  } catch(e) { console.error('fetchUsers failed:', e); }
}

async function fetchGroups() {
  try {
    const r = await fetch(API+'/groups');
    if (r.status === 401) { location.reload(); return; }
    groups = await r.json();
    if (mainView === 'groups') renderGroups();
  } catch(e) { console.error('fetchGroups failed:', e); }
}
async function fetchLive() {
  try {
    const r = await fetch(API+'/live');
    if (r.status === 401) return;
    const data = await r.json();
    const now = Date.now();
    if (prevTime > 0) {
      const dt = (now - prevTime) / 1000;
      for (const [name, s] of Object.entries(data)) {
        const p = prevLive[name];
        if (p) {
          // If counters were reset (new < old), keep previous speed for one cycle
          if (s.up < p.up || s.down < p.down) {
            // Counter reset detected — don't zero out, keep last known speed
          } else {
            speeds[name] = {up: Math.max(0,(s.up-p.up)/dt), down: Math.max(0,(s.down-p.down)/dt)};
          }
        } else if (s.up + s.down > 0) {
          // First time seeing this user — mark as online if they have any traffic
          speeds[name] = {up: s.up > 0 ? 100 : 0, down: s.down > 0 ? 100 : 0};
        }
      }
      for (const name of Object.keys(speeds)) {
        if (!(name in data)) speeds[name] = {up:0, down:0};
      }
    }
    prevLive = data; prevTime = now;
    renderSpeeds();
  } catch(e) { console.error('fetchLive failed:', e); }
}

async function fetchServerInfo() {
  try {
    const r = await fetch(API+'/server-info');
    if (r.ok) {
      serverInfo = await r.json();
      updateProtoBar();
      updateSettingsStatus();
    }
  } catch(e) { console.error('fetchServerInfo failed:', e); }
}

function startPolling() {
  if (polling) return;
  polling = true;
  fetchUsers(); fetchGroups(); fetchLive(); fetchServerInfo(); fetchSystemMonitor();
  setInterval(fetchUsers, 8000);
  setInterval(fetchGroups, 12000);
  setInterval(fetchLive, 3000);
  setInterval(fetchServerInfo, 30000);
  setInterval(fetchSystemMonitor, 15000);
  refreshOpsStatus();
  setInterval(refreshOpsStatus, 30000);
}

function switchMainView(view) {
  mainView = view;
  const ug = document.getElementById('users-grid');
  const gg = document.getElementById('groups-grid');
  const btnG = document.getElementById('btn-groups');
  const btnU = document.getElementById('btn-users');
  if (view === 'groups') {
    ug.style.display = 'none';
    gg.style.display = '';
    btnG.style.display = 'none';
    btnU.style.display = '';
    // hide filter bar counts effect on groups view
    document.querySelector('.filter-bar').style.display = 'none';
    renderGroups();
    fetchGroups();
  } else {
    ug.style.display = '';
    gg.style.display = 'none';
    btnG.style.display = '';
    btnU.style.display = 'none';
    document.querySelector('.filter-bar').style.display = '';
    renderUsers();
  }
}

/* ── Proto Bar ── */
function updateProtoBar() {
  const vm = document.getElementById('pb-vmess');
  const vl = document.getElementById('pb-vless');
  const cd = document.getElementById('pb-cdn');
  const ks = document.getElementById('pb-ks');
  const tr = document.getElementById('pb-trojan');
  const gr = document.getElementById('pb-grpc');
  const hu = document.getElementById('pb-httpupgrade');
  const ss = document.getElementById('pb-ss2022');
  const vw = document.getElementById('pb-vless-ws');
  const fr = document.getElementById('pb-fragment');
  const mx = document.getElementById('pb-mux');
  vm.textContent = 'VMess:' + (serverInfo.vmess_port || 443);
  if (serverInfo.vless) {
    vl.style.display = '';
    vl.textContent = 'VLESS/Reality:' + (serverInfo.vless_port || 2053);
  } else { vl.style.display = 'none'; }
  if (serverInfo.cdn) {
    cd.style.display = '';
    cd.textContent = 'CDN:' + (serverInfo.cdn_domain || '');
  } else { cd.style.display = 'none'; }
  if (serverInfo.trojan) {
    tr.style.display = '';
    tr.textContent = 'Trojan:' + (serverInfo.trojan_port || 2083);
  } else { tr.style.display = 'none'; }
  if (serverInfo.grpc) {
    gr.style.display = '';
    gr.textContent = 'gRPC:' + (serverInfo.grpc_port || 2054);
  } else { gr.style.display = 'none'; }
  if (serverInfo.httpupgrade) {
    hu.style.display = '';
    hu.textContent = 'HU:' + (serverInfo.httpupgrade_port || 2055);
  } else { hu.style.display = 'none'; }
  if (serverInfo.ss2022) {
    ss.style.display = '';
    ss.textContent = 'SS2022:' + (serverInfo.ss2022_port || 2056);
  } else { ss.style.display = 'none'; }
  if (serverInfo.vless_ws) {
    vw.style.display = '';
    vw.textContent = 'VLESS-WS:' + (serverInfo.vless_ws_port || 2057);
  } else { vw.style.display = 'none'; }
  const badgeMap = [
    ['pb-vless-xhttp', 'vless_xhttp', 'XHTTP:', 'vless_xhttp_port', 2053],
    ['pb-vless-vision', 'vless_vision', 'Vision:', 'vless_vision_port', 2058],
    ['pb-vless-reverse', 'vless_reverse', 'Reverse:', 'vless_reverse_port', 2059],
    ['pb-trojan-cdn', 'trojan_cdn', 'Trojan-CDN:', 'trojan_cdn_port', 2083],
    ['pb-hysteria2', 'hysteria2', 'Hy2:', 'hysteria2_port', 8443],
    ['pb-tuic', 'tuic', 'TUIC:', 'tuic_port', 8444],
    ['pb-amneziawg', 'amneziawg', 'AWG:', 'amneziawg_port', 51820],
    ['pb-shadowtls', 'shadowtls', 'STLS:', 'shadowtls_port', 8445],
    ['pb-mieru', 'mieru', 'Mieru:', 'mieru_port', 8446],
    ['pb-naiveproxy', 'naiveproxy', 'Naive:', 'naiveproxy_port', 8447],
    ['pb-wireguard', 'wireguard', 'WG:', 'wireguard_port', 51821],
    ['pb-openvpn', 'openvpn', 'OVPN:', 'openvpn_port', 1194],
  ];
  badgeMap.forEach(([id, key, label, portKey, defPort]) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (serverInfo[key]) {
      el.style.display = '';
      el.textContent = label + (serverInfo[portKey] || defPort);
    } else { el.style.display = 'none'; }
  });
  fr.style.display = serverInfo.fragment_enabled ? '' : 'none';
  mx.style.display = serverInfo.mux_enabled ? '' : 'none';
  // Host Header Spoofing
  const hsEl = document.getElementById('pb-host-spoof');
  if (hsEl) {
    const hostSpoofActive = serverInfo.dpi_http_host_spoof_enabled || serverInfo.dpi_ws_host_front_enabled || serverInfo.dpi_cdn_host_front_enabled || serverInfo.dpi_bug_host_enabled;
    hsEl.style.display = hostSpoofActive ? '' : 'none';
    if (hostSpoofActive) {
      const spoofHosts = [];
      if (serverInfo.dpi_http_host_spoof_enabled) spoofHosts.push('HTTP: ' + (serverInfo.dpi_http_host_spoof_domain || '?'));
      if (serverInfo.dpi_ws_host_front_enabled) spoofHosts.push('WS: ' + (serverInfo.dpi_ws_host_front_domain || '?'));
      if (serverInfo.dpi_cdn_host_front_enabled) spoofHosts.push('CDN: ' + (serverInfo.dpi_cdn_host_front_domain || '?'));
      if (serverInfo.dpi_bug_host_enabled) spoofHosts.push('Bug: ' + (serverInfo.dpi_bug_host_domain || '?'));
      hsEl.textContent = 'Host Spoof: ' + spoofHosts.join(' | ');
    }
  }
  // Domain/CDN Fronting
  const ftEl = document.getElementById('pb-dpi-front');
  if (ftEl) {
    const frontActive = serverInfo.dpi_domain_front || serverInfo.dpi_cdn_front_enabled;
    ftEl.style.display = frontActive ? '' : 'none';
    if (frontActive) {
      const fronts = [];
      if (serverInfo.dpi_domain_front) fronts.push('Domain');
      if (serverInfo.dpi_cdn_front_enabled) fronts.push('CDN');
      ftEl.textContent = 'Front: ' + fronts.join('+');
    }
  }
  // Emergency Relay
  const emEl = document.getElementById('pb-dpi-emergency');
  if (emEl) {
    const emActive = serverInfo.emergency_relay_enabled && serverInfo.emergency_relay_address;
    emEl.style.display = emActive ? '' : 'none';
    if (emActive) {
      emEl.textContent = 'EMERGENCY RELAY: ' + serverInfo.emergency_relay_address;
    }
  }
  const killSwitchOn = asBool(serverInfo.kill_switch);
  ks.textContent = 'Kill Switch: ' + (killSwitchOn ? 'ON' : 'OFF');
  ks.className = 'proto-badge proto-ks' + (killSwitchOn ? '' : ' off');
}

/* ── Filtering ── */
function isOnline(name) {
  const spd = speeds[name] || {up:0, down:0};
  if ((spd.up + spd.down) > 50) return true;
  // Fallback: check online_ip_count from user data (access log based)
  const u = users.find(u => u.name === name);
  if (u && u.online_ip_count > 0) return true;
  return false;
}

function getFilterCounts() {
  const q = (document.getElementById('filter-search')?.value || '').toLowerCase();
  const base = q ? users.filter(u => u.name.toLowerCase().includes(q)) : users;
  return {
    all: base.length,
    online: base.filter(u => isOnline(u.name)).length,
    offline: base.filter(u => u.active && !isOnline(u.name)).length,
    active: base.filter(u => u.active).length,
    disabled: base.filter(u => !u.active).length,
    expiring: base.filter(u => u.active && u.days_left <= 7).length
  };
}

function getFilteredUsers() {
  const q = (document.getElementById('filter-search')?.value || '').toLowerCase();
  let list = users;
  if (q) list = list.filter(u => u.name.toLowerCase().includes(q));
  switch (currentFilter) {
    case 'online':   return list.filter(u => isOnline(u.name));
    case 'offline':  return list.filter(u => u.active && !isOnline(u.name));
    case 'active':   return list.filter(u => u.active);
    case 'disabled': return list.filter(u => !u.active);
    case 'expiring': return list.filter(u => u.active && u.days_left <= 7);
    default:         return list;
  }
}

function updateFilterCounts() {
  const c = getFilterCounts();
  for (const [k, v] of Object.entries(c)) {
    const el = document.getElementById('fc-'+k);
    if (el) el.textContent = v;
  }
}

function applyFilter() { updateFilterCounts(); renderUsers(); }

document.addEventListener('click', e => {
  const pill = e.target.closest('.filter-pill');
  if (!pill) return;
  document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
  pill.classList.add('active');
  currentFilter = pill.dataset.filter;
  applyFilter();
});

/* ── Rendering ── */

// active / disabled / expired / limited (quota used): only "active" is served.
const STATUS_PILL = {
  active: ['online', 'Active'], disabled: ['muted', 'Disabled'],
  expired: ['warning', 'Expired'], limited: ['danger', 'Quota used'],
};
function statusPill(u) {
  const [cls, text] = STATUS_PILL[u.status] || (u.active ? STATUS_PILL.active : STATUS_PILL.disabled);
  return `<span class="status-pill ${cls}">${text}</span>`;
}

function renderUsers() {
  const grid = document.getElementById('users-grid');
  const filtered = getFilteredUsers();
  updateFilterCounts();
  if (!users.length) {
    grid.innerHTML = '<div class="empty-guide">'
      + '<h3>👋 Welcome / خوش آمدید</h3>'
      + '<ol class="help-en"><li>Choose protocols in <b>Settings</b> (Reality + Hysteria2 is a good start).</li>'
      + '<li>Press <b>Add User</b> and pick a plan.</li>'
      + '<li>Send the user their <b>subscription link</b> from the card.</li></ol>'
      + '<ol class="help-fa" lang="fa"><li>در <b>Settings</b> پروتکل‌ها را انتخاب کنید (Reality + Hysteria2 شروع خوبی است).</li>'
      + '<li>روی <b>Add User</b> بزنید و یک پلن انتخاب کنید.</li>'
      + '<li>لینک اشتراک را از کارت کاربر برای او بفرستید.</li></ol>'
      + '<div class="empty-actions">'
      + '<button class="btn btn-primary" onclick="showModal(\'add-modal\')">+ Add User / افزودن کاربر</button>'
      + '<button class="btn btn-outline" onclick="showModal(\'help-modal\')">? Guide / راهنما</button>'
      + '</div></div>';
    return;
  }
  if (!filtered.length) {
    grid.innerHTML = '<div class="empty"><div class="empty-icon">🔍</div><div class="empty-text">No users match this filter</div></div>';
    return;
  }
  grid.innerHTML = '<div class="tactical-table-wrapper"><table class="tactical-table ui-users-table"><thead><tr>'
    + '<th>User</th><th>Bandwidth quota</th><th>Validity</th><th>Live speed</th><th>Status</th><th class="ui-th-end">Actions</th>'
    + '</tr></thead><tbody>' + filtered.map(userRow).join('') + '</tbody></table></div>';
}

function speedCell(spd) {
  return '<span class="up">↑ ' + fmtSpeed(spd.up) + '</span><span class="down">↓ ' + fmtSpeed(spd.down) + '</span>';
}

function quotaClass(pct) { return pct < 60 ? 'online' : (pct < 85 ? 'warning' : 'danger'); }

function userRow(u) {
  const spd = speeds[u.name] || {up:0, down:0};
  const online = isOnline(u.name);
  const n = esc(u.name);
  const pct = Math.max(0, Math.min(100, Number(u.traffic_percent) || 0));
  const days = Number(u.days_left);
  const daysPill = days <= 0 ? ['danger', 'Expired'] : days <= 3 ? ['danger', days + ' days left']
    : days <= 7 ? ['warning', days + ' days left'] : ['muted', days + ' days left'];
  const ipCount = u.online_ip_count || 0;
  const sub = [];
  if (u.note) sub.push(`<span class="note-badge" title="${esc(u.note)}" onclick="event.stopPropagation();promptEditNote('${jsq(u.name)}','${jsq(u.note)}')">${esc(u.note)}</span>`);
  if (ipCount > 0) sub.push(`<button type="button" onclick="showUserIPs('${jsq(u.name)}')" title="Connected IPs">${ipCount} IP${ipCount > 1 ? 's' : ''}</button>`);
  sub.push(`<button type="button" title="Speed limit (click to edit)" onclick="promptSpeed('${jsq(u.name)}',${Number(u.speed_limit_down) || 0},${Number(u.speed_limit_up) || 0})">⚡ ${Number(u.speed_limit_down) || 0} KB/s</button>`);
  const initials = esc(String(u.name).replace(/[^\p{L}\p{N}]/gu, '').slice(0, 2) || '?');
  return `<tr id="card-${n}" class="${u.active ? '' : 'is-inactive'}">
    <td><div class="ui-user-cell">
      <span class="ui-avatar${u.active ? '' : ' is-off'}">${initials}</span>
      <div><div class="ui-user-name"><span class="online-dot ${online ? 'on' : ''}" id="dot-${n}"></span>${n}</div>
      <div class="ui-user-sub">${sub.join('<span>·</span>')}</div></div>
    </div></td>
    <td><div class="ui-quota">
      <div class="ui-quota-top"><span>${fmtTraffic(u.traffic_used_bytes)}</span><span>/ ${fmtTraffic(u.traffic_limit_bytes)}</span></div>
      <progress class="ops-progress ops-progress-${quotaClass(pct)} ui-quota-progress" max="100" value="${pct}"></progress>
      <div class="ui-quota-foot">${pct}% consumed</div>
    </div></td>
    <td><div class="tactical-mono">${esc(u.expire_at || '—')}</div><div class="ui-days"><span class="status-pill ${daysPill[0]}">${daysPill[1]}</span></div></td>
    <td><div class="ui-speed" id="speed-${n}">${speedCell(spd)}</div></td>
    <td>${statusPill(u)}</td>
    <td><div class="ui-row-actions">
      <button type="button" class="ui-icon-btn" title="Config &amp; QR" onclick="showConfig('${jsq(u.name)}')"><span class="material-symbols-outlined">qr_code_2</span></button>
      <button type="button" class="ui-icon-btn" title="Activity" onclick="showActivity('${jsq(u.name)}')"><span class="material-symbols-outlined">history</span></button>
      <button type="button" class="ui-icon-btn" title="Renew" onclick="showRenew('${jsq(u.name)}')"><span class="material-symbols-outlined">event_repeat</span></button>
      <button type="button" class="ui-icon-btn is-ok" title="Add traffic without reset" onclick="showAddTraffic('${jsq(u.name)}')"><span class="material-symbols-outlined">data_saver_on</span></button>
      <button type="button" class="ui-icon-btn" title="${u.active ? 'Disconnect' : 'Connect'}" onclick="toggleUser('${jsq(u.name)}')"><span class="material-symbols-outlined">${u.active ? 'pause_circle' : 'play_circle'}</span></button>
      <button type="button" class="ui-icon-btn is-danger" title="Delete" onclick="deleteUser('${jsq(u.name)}')"><span class="material-symbols-outlined">delete</span></button>
    </div></td>
  </tr>`;
}

function renderGroups() {
  const grid = document.getElementById('groups-grid');
  if (!groups || !groups.length) {
    grid.innerHTML = '<div class="empty"><div class="empty-icon">🧩</div><div class="empty-text">No groups yet</div></div>';
    return;
  }
  grid.innerHTML = groups.map(g => {
    const pct = g.count ? Math.round((g.active / g.count) * 100) : 0;
    const gid = esc(g.id);
    return `<div class="ui-group">
      <div class="ui-group-head">
        <span class="ui-group-icon material-symbols-outlined">workspaces</span>
        <div class="ui-minw0"><div class="ui-group-name">${gid}</div>
          <div class="ops-cell-sub">${esc(String(g.traffic_gb || 0))} GB each · latest expiry ${esc((g.latest_expire || '').slice(0, 10) || '—')}</div></div>
      </div>
      <div class="ui-group-stats">
        <div><span>Users</span><strong>${Number(g.count) || 0}</strong></div>
        <div><span>Active</span><strong>${Number(g.active) || 0} <small class="tactical-muted">(${pct}%)</small></strong></div>
      </div>
      <progress class="ops-progress ops-progress-online" max="100" value="${pct}"></progress>
      <div class="ui-group-actions">
        <button class="btn btn-outline btn-sm" onclick="openGroupExport('${jsq(g.id)}')"><span class="material-symbols-outlined">ios_share</span>Export</button>
        <button class="btn btn-outline btn-sm" onclick="openGroupUsers('${jsq(g.id)}')"><span class="material-symbols-outlined">open_in_new</span>Open</button>
        <button class="btn btn-danger btn-sm" onclick="deleteGroup('${jsq(g.id)}')"><span class="material-symbols-outlined">delete</span></button>
      </div>
    </div>`;
  }).join('');
}

async function openGroupUsers(groupId) {
  // Reuse bulk output tab system: create a new run tab from group data
  const outEl = document.getElementById('bulk-output');
  outEl.value = 'Loading group...';
  showModal('bulk-modal');
  try {
    const r = await fetch(API+'/groups/'+encodeURIComponent(groupId)+'/users');
    const d = await r.json();
    if (!d.ok) { toast(d.error||'Error','error'); return; }
    const users = d.users || [];
    const stamp = new Date();
    const hh = String(stamp.getHours()).padStart(2,'0');
    const mm = String(stamp.getMinutes()).padStart(2,'0');
    const label = `${groupId} · open · ${users.length} · ${hh}:${mm}`;
    const text = formatBulkText({
      prefix: groupId,
      created: users.length,
      traffic: '',
      days: '',
      numbered: true,
      start: '',
      pad: '',
      note: 'Exported from Groups section',
      users
    });
    const runId = 'grp_' + Date.now() + '_' + Math.random().toString(16).slice(2);
    _bulkRuns.unshift({ id: runId, label, meta: {prefix: groupId, created: users.length}, users, text });
    _bulkActiveRunId = runId;
    renderBulkTabs();
    setBulkOutputForActive();
  } catch(e) { toast('Connection error','error'); }
}

function openGroupExport(groupId) {
  openGroupUsers(groupId);
  setTimeout(()=>{ try { openBulkInNewTab(); } catch(e) {} }, 300);
}

async function deleteGroup(groupId) {
  const applyNow = false; // keep safe; user can Sync later
  if (!await uiConfirm(`Delete group "${groupId}" from database?\n\nThis will not reload server (no disruption). Use Sync later to apply.`)) return;
  try {
    // Delete by prefix (groupId includes gb slug too)
    const r = await fetch(API+'/bulk-delete', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ prefix: groupId, apply: applyNow })
    });
    const d = await r.json();
    if (!d.ok) { toast(d.error||'Error','error'); return; }
    toast(`Deleted ${d.deleted} users`);
    fetchGroups(); fetchUsers();
  } catch(e) { toast('Connection error','error'); }
}

function renderSpeeds() {
  let onlineCount = 0;
  for (const u of users) {
    const spd = speeds[u.name] || {up:0, down:0};
    const online = isOnline(u.name);
    if (online) onlineCount++;
    const el = document.getElementById('speed-'+u.name);
    if (el) el.innerHTML = speedCell(spd);
    const dot = document.getElementById('dot-'+u.name);
    if (dot) dot.className = 'online-dot'+(online?' on':'');
  }
  document.getElementById('s-online').textContent = onlineCount;
  updateFilterCounts();
}

function updateStats() {
  const total = users.length;
  const active = users.filter(u=>u.active).length;
  const totalBytes = users.reduce((s,u)=>s+(u.traffic_used_bytes||0), 0);
  document.getElementById('s-total').textContent = total;
  document.getElementById('s-active').textContent = active;
  document.getElementById('s-traffic').textContent = fmtTraffic(totalBytes);
  const exp = document.getElementById('s-expiring');
  if (exp) exp.textContent = users.filter(u => u.active && u.days_left <= 7).length;
  updateFilterCounts();
}

/* ── Actions ── */
async function doAddUser() {
  const name = document.getElementById('add-name').value.trim();
  const traffic = parseFloat(document.getElementById('add-traffic').value);
  const days = parseInt(document.getElementById('add-days').value);
  const note = (document.getElementById('add-note').value || '').trim();
  const speedOr = (id) => { const v = parseInt(document.getElementById(id).value); return Number.isNaN(v) ? 0 : Math.max(0, v); };
  const speed_limit_down = speedOr('add-speed-down');
  const speed_limit_up = speedOr('add-speed-up');
  if (!name) {toast('Please enter a username / نام کاربری را وارد کنید','error'); return;}
  if (Number.isNaN(traffic) || traffic < 0) {toast('Traffic must be 0 (unlimited) or more / حجم نامعتبر است','error'); return;}
  if (Number.isNaN(days) || days < 0) {toast('Days must be 0 (never expires) or more / مدت نامعتبر است','error'); return;}
  try {
    const d = await apiCall(API+'/users', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name, traffic, days, speed_limit_up, speed_limit_down, note})});
    if (d.ok) {
      closeModal('add-modal');
      document.getElementById('add-name').value = '';
      document.getElementById('add-note').value = '';
      document.getElementById('add-speed-down').value = '0';
      document.getElementById('add-speed-up').value = '0';
      toast('User '+name+' created');
      fetchUsers();
      setTimeout(()=>showConfig(name), 1500);
    } else { toast(d.error||'Create failed','error'); }
  } catch (e) { /* apiCall already toasted */ }
}

let _bulkLastUsers = [];
let _bulkRuns = [];
let _bulkActiveRunId = '';

async function doBulkCreate() {
  const prefix = document.getElementById('bulk-prefix').value.trim() || 'group';
  const count = parseInt(document.getElementById('bulk-count').value) || 1;
  const traffic = parseFloat(document.getElementById('bulk-traffic').value) || 1;
  const days = parseInt(document.getElementById('bulk-days').value) || 30;
  const numbered = document.getElementById('bulk-numbered').value === '1';
  const start = parseInt(document.getElementById('bulk-start').value) || 1;
  const pad = parseInt(document.getElementById('bulk-pad').value) || 3;
  // 0 = unlimited (`|| 200` used to make 0 impossible to enter)
  const speed_limit_down = Math.max(0, parseInt(document.getElementById('bulk-speed-down').value) || 0);
  const speed_limit_up = Math.max(0, parseInt(document.getElementById('bulk-speed-up').value) || 0);
  const apply = document.getElementById('bulk-apply').checked;
  if (apply && !await uiConfirm('Apply to server now? This may reload config.')) return;

  const outEl = document.getElementById('bulk-output');
  outEl.value = 'Creating...';
  try {
    const r = await fetch(API+'/bulk-users', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({prefix, count, traffic, days, numbered, start, pad, apply, speed_limit_up, speed_limit_down})
    });
    const d = await r.json();
    if (!d.ok) { outEl.value = d.error || 'Error'; renderBulkQrGrid([]); toast(d.error||'Error','error'); return; }
    _bulkLastUsers = d.users || [];
    toast(`Created ${d.created} users` + (d.apply ? ' (applied)' : ' (not applied)'));
    fetchUsers();

    const stamp = new Date();
    const hh = String(stamp.getHours()).padStart(2,'0');
    const mm = String(stamp.getMinutes()).padStart(2,'0');
    const label = `${prefix} · ${traffic}GB · ${d.created} · ${hh}:${mm}`;

    const text = formatBulkText({
      prefix,
      created: d.created,
      traffic,
      days,
      numbered: !!d.numbered,
      start: d.start,
      pad: d.pad,
      note: d.note,
      users: _bulkLastUsers
    });

    const runId = 'run_' + Date.now() + '_' + Math.random().toString(16).slice(2);
    _bulkRuns.unshift({ id: runId, label, meta: {prefix, traffic, days, created: d.created}, users: _bulkLastUsers, text });
    _bulkActiveRunId = runId;
    renderBulkTabs();
    setBulkOutputForActive();

    // Try opening a new tab (user-initiated click => usually allowed)
    try { openBulkInNewTab(); } catch(e) {}
  } catch(e) {
    outEl.value = 'Connection error';
    renderBulkQrGrid([]);
    toast('Connection error','error');
  }
}

function formatBulkText({prefix, created, traffic, days, numbered, start, pad, note, users}) {
  const plan = (traffic !== '' && days !== '') ? `${traffic} GB for ${days} days` : '—';
  const naming = (start !== '' && pad !== '') ? (numbered ? ('numbered from ' + start + ' (pad ' + pad + ')') : 'random') : (numbered ? 'numbered' : 'random');
  const list = users || [];
  let text = `# GROUP: ${prefix}\\n` +
             `# PLAN: ${plan}\\n` +
             `# NAMING: ${naming}\\n` +
             `# CREATED: ${created}\\n` +
             `# NOTE: ${note}\\n` +
             `#\\n` +
             `# HOW TO COPY ONE CONFIG: Select everything from <<<BEGIN:...>>> through <<<END:...>>> (inclusive).\\n` +
             `# Or split text by lines that start with <<<BEGIN:\\n\\n`;

  const gap = '\\n\\n\\n\\n\\n';
  list.forEach((u, idx) => {
    if (idx > 0) text += gap;
    const n = idx + 1;
    const tag = u.name;
    text += `<<<BEGIN:${tag}>>>\\n`;
    text += `#${n} / ${list.length} — ${tag}\\n`;
    text += `Copy from BEGIN to END for this user only.\\n\\n`;
    if (u.vmess) text += `VMess:\\n${u.vmess}\\n\\n`;
    if (u.vless) text += `VLESS:\\n${u.vless}\\n\\n`;
    if (u.cdn_vmess) text += `CDN VMess:\\n${u.cdn_vmess}\\n\\n`;
    if (u.trojan) text += `Trojan:\\n${u.trojan}\\n\\n`;
    if (u.grpc_vmess) text += `gRPC VMess:\\n${u.grpc_vmess}\\n\\n`;
    if (u.httpupgrade_vmess) text += `HTTPUpgrade VMess:\\n${u.httpupgrade_vmess}\\n\\n`;
    text += `<<<END:${tag}>>>\\n`;
  });
  return text;
}

function renderBulkTabs() {
  const tabsEl = document.getElementById('bulk-tabs');
  if (!_bulkRuns.length) { tabsEl.style.display='none'; tabsEl.innerHTML=''; return; }
  tabsEl.style.display = '';
  tabsEl.innerHTML = _bulkRuns.slice(0, 12).map(r => {
    const active = r.id === _bulkActiveRunId;
    return `<button class="bulk-tab ${active?'active':''}" onclick="selectBulkRun('${jsq(r.id)}')">${esc(r.label||'group')}</button>`;
  }).join('');
}

function selectBulkRun(id) {
  _bulkActiveRunId = id;
  renderBulkTabs();
  setBulkOutputForActive();
}

function getActiveBulkRun() {
  return _bulkRuns.find(r => r.id === _bulkActiveRunId) || _bulkRuns[0] || null;
}

function setBulkOutputForActive() {
  const outEl = document.getElementById('bulk-output');
  const run = getActiveBulkRun();
  if (!run) {
    outEl.value = '';
    renderBulkQrGrid([]);
    return;
  }
  _bulkLastUsers = run.users || [];
  outEl.value = run.text || '';
  renderBulkQrGrid(run.users || []);
}

function renderBulkQrGrid(users) {
  const wrap = document.getElementById('bulk-qr-wrap');
  if (!wrap) return;
  if (!users || !users.length) {
    wrap.innerHTML = '';
    wrap.style.display = 'none';
    return;
  }
  if (typeof qrcode !== 'function') {
    wrap.innerHTML = '<div style="color:var(--t3);font-size:12px">QR library not loaded. Refresh the page.</div>';
    wrap.style.display = 'block';
    return;
  }
  wrap.style.display = 'grid';
  wrap.innerHTML = users.map((u, i) => {
    const addQr = (label, link) => {
      if (!link) return '';
      try {
        const qr = qrcode(0, 'M');
        qr.addData(link);
        qr.make();
        const svg = qr.createSvgTag(3, 0);
        return `<div class="bulk-qr-item"><span class="bulk-qr-lbl">${esc(label)}</span>${svg}</div>`;
      } catch (e) { return ''; }
    };
    const bits = [addQr('VMess', u.vmess), addQr('VLESS', u.vless), addQr('CDN', u.cdn_vmess), addQr('Trojan', u.trojan), addQr('gRPC', u.grpc_vmess), addQr('HU', u.httpupgrade_vmess), addQr('SS2022', u.ss2022), addQr('VL-WS', u.vless_ws)].filter(Boolean).join('');
    if (!bits) return '';
    return `<div class="bulk-qr-card">
      <div class="bulk-qr-title">${esc(u.name)}<small>#${i + 1}/${users.length}</small></div>
      <div class="bulk-qr-row">${bits}</div>
    </div>`;
  }).join('');
}

async function downloadBulkZip() {
  const run = getActiveBulkRun();
  if (!run || !run.users || !run.users.length) return toast('No bulk results yet','error');
  const prefix = (run.meta && run.meta.prefix) != null ? String(run.meta.prefix) : 'bulk';
  try {
    const r = await fetch(API + '/bulk-export-zip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prefix, users: run.users }),
      credentials: 'same-origin'
    });
    const ct = (r.headers.get('content-type') || '').toLowerCase();
    if (!r.ok) {
      let msg = 'ZIP failed';
      if (ct.includes('application/json')) {
        try { const d = await r.json(); if (d.error) msg = d.error; } catch (e) {}
      }
      toast(msg, 'error');
      return;
    }
    const blob = await r.blob();
    const safePrefix = prefix.replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 80) || 'bulk';
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${safePrefix}-vpn-configs.zip`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 2500);
    toast('ZIP downloaded');
  } catch (e) {
    toast('Connection error', 'error');
  }
}

function copyBulkOutput() {
  const ta = document.getElementById('bulk-output');
  if (!ta.value) return toast('Nothing to copy','error');
  _copyText(ta.value).then(()=>toast('Copied')).catch(()=>toast('Copied'));
}

function downloadBulkCSV() {
  if (!_bulkLastUsers.length) return toast('No bulk results yet','error');
  const rows = [['name','vmess','vless','cdn_vmess','trojan','grpc_vmess','httpupgrade_vmess','ss2022','vless_ws']];
  _bulkLastUsers.forEach(u => rows.push([u.name, u.vmess||'', u.vless||'', u.cdn_vmess||'', u.trojan||'', u.grpc_vmess||'', u.httpupgrade_vmess||'', u.ss2022||'', u.vless_ws||'']));
  const csv = rows.map(r => r.map(v => '\"'+String(v).replace(/\"/g,'\"\"')+'\"').join(',')).join('\\n');
  const blob = new Blob([csv], {type:'text/csv;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  const run = getActiveBulkRun();
  const p = (run && run.meta && run.meta.prefix) ? run.meta.prefix : 'bulk';
  a.download = `${p}-bulk-configs.csv`;
  document.body.appendChild(a);
  a.click();
  setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

function openBulkInNewTab() {
  const run = getActiveBulkRun();
  if (!run || !run.text) return toast('No bulk results yet','error');
  const w = window.open('', '_blank');
  if (!w) { toast('Popup blocked — allow popups for this site','error'); return; }
  const safe = run.text.replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const usersArr = (run.users || []).map(u => ({
    name: String(u.name || ''),
    vmess: u.vmess || '',
    vless: u.vless || '',
    cdn: u.cdn_vmess || '',
    trojan: u.trojan || '',
    grpc: u.grpc_vmess || '',
    httpupgrade: u.httpupgrade_vmess || '',
    ss2022: u.ss2022 || '',
    vless_ws: u.vless_ws || ''
  }));
  let usersJson = JSON.stringify(usersArr).replace(/</g, '\\u003c');
  const ttl = String((run.meta && run.meta.prefix) || 'Bulk Configs')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
  w.document.open();
  w.document.write(`<!doctype html><html><head><meta charset=\"utf-8\"><title>VIP Premium Panel</title>
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <style nonce=\"${window.__CSP_NONCE__||''}\">
    body{margin:0;background:#0b1020;color:#e6edf3;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
    .bar{position:sticky;top:0;background:#0d1117;border-bottom:1px solid #2d333b;padding:10px 12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;z-index:10}
    button{background:#1f6feb;border:none;color:#fff;border-radius:10px;padding:8px 12px;font-weight:800;cursor:pointer}
    button.secondary{background:transparent;border:1px solid #3d444d;color:#c9d1d9}
    .wrap{padding:14px;max-width:1200px;margin:0 auto}
    h2{font-size:15px;color:#58a6ff;margin:20px 0 12px;font-family:system-ui,sans-serif}
    .qr-user{margin:0 0 20px;padding:16px;border:1px solid #2d333b;border-radius:14px;background:#0d1117}
    .qr-user h3{margin:0 0 12px;font-size:14px;color:#58a6ff;font-family:system-ui,sans-serif}
    .qr-row{display:flex;flex-wrap:wrap;gap:18px;align-items:flex-start}
    .qr-item{text-align:center}
    .qr-item .lbl{font-size:11px;color:#8b949e;margin-bottom:6px}
    .qr-item svg{display:block;background:#fff;border-radius:10px;padding:6px}
    pre{white-space:pre-wrap;word-break:break-word;background:#0d1117;border:1px solid #2d333b;border-radius:14px;padding:14px;line-height:1.5}
    .hint{color:#8b949e;font-family:system-ui, -apple-system, Segoe UI, sans-serif;font-size:12px;max-width:520px}
  </style></head><body>
    <div class=\"bar\">
      <button id=\"copy\">Copy text</button>
      <button class=\"secondary\" id=\"close\">Close</button>
      <span class=\"hint\">QRs for all users below. Text export: copy blocks between BEGIN and END.</span>
    </div>
    <div class=\"wrap\">
      <h2>QR codes (all)</h2>
      <div id=\"qr-root\"></div>
      <h2>Text export</h2>
      <pre id=\"txt\">${safe}</pre>
    </div>
    <script nonce=\"${window.__CSP_NONCE__||''}\" type=\"application/json\" id=\"bulk-json\">${usersJson}<\/script>
    <script nonce=\"${window.__CSP_NONCE__||''}\" src=\"${QR_LIB_URL}\"><\/script>
    <script nonce=\"${window.__CSP_NONCE__||''}\">
      (function(){
        var users = JSON.parse(document.getElementById('bulk-json').textContent);
        var root = document.getElementById('qr-root');
        users.forEach(function(u, i) {
          var sec = document.createElement('section');
          sec.className = 'qr-user';
          var h = document.createElement('h3');
          h.textContent = u.name + '  (' + (i+1) + '/' + users.length + ')';
          sec.appendChild(h);
          var row = document.createElement('div');
          row.className = 'qr-row';
          function add(label, link) {
            if (!link) return;
            var qr = qrcode(0, 'M');
            qr.addData(link);
            qr.make();
            var box = document.createElement('div');
            box.className = 'qr-item';
            var lbl = document.createElement('div');
            lbl.className = 'lbl';
            lbl.textContent = label;
            box.appendChild(lbl);
            var holder = document.createElement('div');
            holder.innerHTML = qr.createSvgTag(4, 0);
            box.appendChild(holder);
            row.appendChild(box);
          }
          add('VMess', u.vmess);
          add('VLESS', u.vless);
          add('CDN', u.cdn);
          add('Trojan', u.trojan);
          add('gRPC', u.grpc);
          add('HU', u.httpupgrade);
          add('SS2022', u.ss2022);
          add('VL-WS', u.vless_ws);
          sec.appendChild(row);
          root.appendChild(sec);
        });
        var t = document.getElementById('txt').innerText;
        document.getElementById('copy').onclick = function(){
          if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t);return;}
          var a=document.createElement('textarea');a.value=t;a.style.cssText='position:fixed;left:-9999px;opacity:0';
          document.body.appendChild(a);a.focus();a.select();try{document.execCommand('copy')}catch(e){}
          document.body.removeChild(a);
        };
        document.getElementById('close').onclick = function(){ window.close(); };
      })();
    <\/script>
  </body></html>`);
  w.document.close();
}

async function deleteBulkGroup() {
  const run = getActiveBulkRun();
  if (!run || !run.users || !run.users.length) return toast('No group selected','error');
  const applyNow = document.getElementById('bulk-apply').checked;
  const prefix = run.meta?.prefix || 'group';
  const msg = `Delete this group?\n\nPrefix: ${prefix}\nUsers: ${run.users.length}\n\nThis will remove users from the database.` +
              (applyNow ? `\n\nApply is ON: server config will reload.` : `\n\nApply is OFF: no disruption now (they won't be removed from server until Sync).`);
  if (!await uiConfirm(msg)) return;

  try {
    const r = await fetch(API+'/bulk-delete', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ names: run.users.map(u=>u.name), apply: applyNow })
    });
    const d = await r.json();
    if (!d.ok) { toast(d.error||'Error','error'); return; }
    toast(`Deleted ${d.deleted} users` + (d.apply ? ' (applied)' : ''));
    // remove tab
    _bulkRuns = _bulkRuns.filter(x => x.id !== run.id);
    _bulkActiveRunId = _bulkRuns[0]?.id || '';
    renderBulkTabs();
    setBulkOutputForActive();
    fetchUsers();
  } catch(e) {
    toast('Connection error','error');
  }
}

async function toggleUser(name) {
  const u = users.find(x=>x.name===name);
  const action = u && u.active ? 'disconnect' : 'reconnect';
  if (!await uiConfirm(`${action === 'disconnect' ? 'Disconnect' : 'Reconnect'} "${name}"?`)) return;
  try {
    const d = await apiCall(API+'/users/'+encodeURIComponent(name)+'/toggle', {method:'POST'});
    if (d.ok) { toast(d.message); fetchUsers(); }
    else toast(d.error||'Action failed','error');
  } catch (e) { /* apiCall already toasted */ }
}

async function deleteUser(name) {
  if (!await uiConfirm('Are you sure you want to delete "'+name+'"?')) return;
  try {
    const d = await apiCall(API+'/users/'+encodeURIComponent(name), {method:'DELETE'});
    if (d.ok) { toast(name+' deleted'); fetchUsers(); }
    else toast(d.error||'Delete failed','error');
  } catch (e) { /* apiCall already toasted */ }
}

function showRenew(name) {
  renewTarget = name;
  document.getElementById('renew-name').textContent = name;
  const u = users.find(x=>x.name===name);
  if (u) { document.getElementById('renew-traffic').value = u.traffic_limit; document.getElementById('renew-days').value = 30; }
  showModal('renew-modal');
}

async function doRenewUser() {
  const traffic = parseFloat(document.getElementById('renew-traffic').value);
  const days = parseInt(document.getElementById('renew-days').value);
  try {
    const d = await apiCall(API+'/users/'+encodeURIComponent(renewTarget)+'/renew',
      {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({traffic, days})});
    if (d.ok) { closeModal('renew-modal'); toast(renewTarget+' renewed'); fetchUsers(); }
    else toast(d.error||'Renew failed','error');
  } catch (e) { /* apiCall already toasted */ }
}

/* ── Config Modal (multi-protocol tabs) ── */
// Config tab -> the user-dict field holding its link (same name otherwise).
const CONFIG_LINK_FIELD = {cdn: 'cdn_vmess', grpc: 'grpc_vmess', httpupgrade: 'httpupgrade_vmess'};

function showConfig(name) {
  const u = users.find(x=>x.name===name);
  if (!u) return;
  configTarget = u;
  document.getElementById('config-name').textContent = name;

  // A tab shows only when the server really serves that protocol to this
  // user: the panel builds a link only then (ShadowTLS has no link format;
  // it ships in the sing-box / Clash subscriptions).
  const visible = [];
  document.querySelectorAll('#config-tabs .config-tab').forEach(t => {
    const key = [...t.classList].find(c => c.startsWith('tab-')).slice(4);
    const on = key === 'shadowtls'
      ? !!(serverInfo.shadowtls_enabled && serverInfo.engines && serverInfo.engines['sing-box'])
      : key === 'naiveproxy'
        ? !!(u.naiveproxy || (serverInfo.naiveproxy_enabled && serverInfo.engines && serverInfo.engines['sing-box']))
        : !!u[CONFIG_LINK_FIELD[key] || key];
    t.style.display = on ? '' : 'none';
    if (on) visible.push(key);
  });
  configTab = visible[0] || 'vmess';
  document.querySelectorAll('.config-tab').forEach(t => t.classList.remove('active'));
  const first = document.querySelector('.tab-' + configTab);
  if (first) first.classList.add('active');
  renderConfigTab();
  // Sub links: the page, and the two app profiles
  const subUrl = location.origin + '/sub/' + u.uuid;
  document.getElementById('config-sub-url').value = subUrl;
  document.getElementById('config-sub-open').href = subUrl;
  document.getElementById('config-sub-singbox').value = location.origin + '/sub-singbox/' + u.uuid;
  document.getElementById('config-sub-clash').value = location.origin + '/sub-clash/' + u.uuid;
  showModal('config-modal');
}

function switchConfigTab(tab) {
  configTab = tab;
  document.querySelectorAll('.config-tab').forEach(t => t.classList.remove('active'));
  document.querySelector('.tab-'+tab).classList.add('active');
  renderConfigTab();
}

function renderConfigTab() {
  const u = configTarget;
  if (!u) return;
  let link = '', label = '', info = '';
  if (configTab === 'vmess') {
    link = u.vmess;
    label = 'VMess Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:var(--accent)">VMess + WS + TLS</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.vmess_port || 443}</span>
      <span class="ck">UUID</span><span class="cv" style="font-size:10px;word-break:break-all">${u.uuid}</span>
      <span class="ck">Network</span><span class="cv">WebSocket</span>
      <span class="ck">Path</span><span class="cv">${serverInfo.vmess_ws_path || '/api/v1/stream'}</span>
      <span class="ck">TLS</span><span class="cv">Enabled</span>
      <span class="ck">SNI</span><span class="cv">${esc(serverInfo.vmess_sni || SERVER_INFO.sni || '')}</span>`;
  } else if (configTab === 'vless') {
    link = u.vless || '';
    label = 'VLESS Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:var(--purple)">VLESS + Reality</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.vless_port || 2053}</span>
      <span class="ck">UUID</span><span class="cv" style="font-size:10px;word-break:break-all">${u.uuid}</span>
      <span class="ck">Flow</span><span class="cv">xtls-rprx-vision</span>
      <span class="ck">Security</span><span class="cv">Reality</span>
      <span class="ck">SNI</span><span class="cv">${serverInfo.vless_sni || ''}</span>
      <span class="ck">Fingerprint</span><span class="cv">chrome</span>
      <span class="ck">Public Key</span><span class="cv" style="font-size:9px;word-break:break-all">${serverInfo.vless_public_key || ''}</span>
      <span class="ck">Short ID</span><span class="cv">${serverInfo.vless_short_id || ''}</span>`;
  } else if (configTab === 'cdn') {
    link = u.cdn_vmess || '';
    label = 'CDN VMess Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:var(--orange)">VMess + WS + TLS (CDN)</span>
      <span class="ck">Server</span><span class="cv">${serverInfo.cdn_domain || ''}</span>
      <span class="ck">Port</span><span class="cv">443</span>
      <span class="ck">UUID</span><span class="cv" style="font-size:10px;word-break:break-all">${u.uuid}</span>
      <span class="ck">Network</span><span class="cv">WebSocket</span>
      <span class="ck">Path</span><span class="cv">${serverInfo.cdn_ws_path || '/cdn-ws'}</span>
      <span class="ck">TLS</span><span class="cv">Enabled (Cloudflare)</span>
      <span class="ck">Host</span><span class="cv">${serverInfo.cdn_domain || ''}</span>`;
  } else if (configTab === 'trojan') {
    link = u.trojan || '';
    label = 'Trojan Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#e74c3c">Trojan + TLS</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.trojan_port || 2083}</span>
      <span class="ck">Password</span><span class="cv" style="font-size:10px;word-break:break-all">${u.uuid}</span>
      <span class="ck">Network</span><span class="cv">TCP</span>
      <span class="ck">Security</span><span class="cv">TLS</span>
      <span class="ck">SNI</span><span class="cv">${SERVER_INFO.sni}</span>`;
  } else if (configTab === 'grpc') {
    link = u.grpc_vmess || '';
    label = 'gRPC VMess Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#2ecc71">VMess + gRPC + TLS</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.grpc_port || 2054}</span>
      <span class="ck">UUID</span><span class="cv" style="font-size:10px;word-break:break-all">${u.uuid}</span>
      <span class="ck">Network</span><span class="cv">gRPC (multi-mode)</span>
      <span class="ck">Service</span><span class="cv">${serverInfo.grpc_service || 'GunService'}</span>
      <span class="ck">TLS</span><span class="cv">Enabled</span>
      <span class="ck">ALPN</span><span class="cv">h2</span>`;
  } else if (configTab === 'httpupgrade') {
    link = u.httpupgrade_vmess || '';
    label = 'HTTPUpgrade VMess Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#3498db">VMess + HTTPUpgrade + TLS</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.httpupgrade_port || 2055}</span>
      <span class="ck">UUID</span><span class="cv" style="font-size:10px;word-break:break-all">${u.uuid}</span>
      <span class="ck">Network</span><span class="cv">HTTPUpgrade</span>
      <span class="ck">Path</span><span class="cv">${serverInfo.httpupgrade_path || '/httpupgrade'}</span>
      <span class="ck">TLS</span><span class="cv">Enabled</span>
      <span class="ck">SNI</span><span class="cv">${SERVER_INFO.sni}</span>`;
  } else if (configTab === 'ss2022') {
    link = u.ss2022 || '';
    label = 'ShadowSocks 2022 Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#e67e22">ShadowSocks 2022</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.ss2022_port || 2056}</span>
      <span class="ck">Method</span><span class="cv">AEAD-2022-BLAKE3</span>
      <span class="ck">Network</span><span class="cv">TCP + UDP</span>
      <span class="ck">Type</span><span class="cv">Per-user key derived from UUID</span>`;
  } else if (configTab === 'vless_ws') {
    link = u.vless_ws || '';
    label = 'VLESS WebSocket Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#1abc9c">VLESS + WS + TLS</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.vless_ws_port || 2057}</span>
      <span class="ck">UUID</span><span class="cv" style="font-size:10px;word-break:break-all">${u.uuid}</span>
      <span class="ck">Network</span><span class="cv">WebSocket</span>
      <span class="ck">Path</span><span class="cv">${serverInfo.vless_ws_path || '/vless-ws'}</span>
      <span class="ck">TLS</span><span class="cv">Enabled</span>
      <span class="ck">SNI</span><span class="cv">${SERVER_INFO.sni}</span>`;
  } else if (configTab === 'vless_xhttp') {
    link = u.vless_xhttp || '';
    label = 'VLESS XHTTP Reality Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#e056fd">VLESS + XHTTP + Reality</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.vless_xhttp_port || 2053}</span>
      <span class="ck">Transport</span><span class="cv">XHTTP (${serverInfo.vless_xhttp_mode || 'auto'})</span>
      <span class="ck">Path</span><span class="cv">${serverInfo.vless_xhttp_path || '/xhttp-stream'}</span>
      <span class="ck">Security</span><span class="cv">Reality</span>`;
  } else if (configTab === 'vless_vision') {
    link = u.vless_vision || '';
    label = 'VLESS Vision Reality Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#6c5ce7">VLESS + Reality + Vision</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.vless_vision_port || 2058}</span>
      <span class="ck">Flow</span><span class="cv">xtls-rprx-vision</span>
      <span class="ck">Security</span><span class="cv">Reality</span>`;
  } else if (configTab === 'vless_reverse') {
    link = u.vless_reverse || '';
    label = 'VLESS Reverse Reality Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#fd79a8">VLESS Reverse Reality</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.vless_reverse_port || 2059}</span>
      <span class="ck">Mode</span><span class="cv">Reverse Tunnel (${serverInfo.vless_reverse_backhaul_mode || 'rathole'})</span>
      <span class="ck">Security</span><span class="cv">Reality</span>`;
  } else if (configTab === 'trojan_cdn') {
    link = u.trojan_cdn || '';
    label = 'Trojan CDN Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#e74c3c">Trojan + WS + CDN</span>
      <span class="ck">Server</span><span class="cv">${serverInfo.trojan_cdn_domain || SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.trojan_cdn_port || 2083}</span>
      <span class="ck">Transport</span><span class="cv">WebSocket</span>
      <span class="ck">Path</span><span class="cv">${serverInfo.trojan_cdn_ws_path || '/trojan-ws'}</span>`;
  } else if (configTab === 'hysteria2') {
    link = u.hysteria2 || '';
    label = 'Hysteria2 Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#00cec9">Hysteria2 (QUIC)</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.hysteria2_port || 8443}</span>
      <span class="ck">Transport</span><span class="cv">QUIC/UDP</span>
      <span class="ck">Obfuscation</span><span class="cv">${serverInfo.hysteria2_salamander ? 'Salamander' : 'None'}</span>`;
  } else if (configTab === 'tuic') {
    link = u.tuic || '';
    label = 'TUIC v5 Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#0984e3">TUIC v5 (QUIC)</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.tuic_port || 8444}</span>
      <span class="ck">Transport</span><span class="cv">QUIC/UDP</span>
      <span class="ck">Congestion</span><span class="cv">${serverInfo.tuic_congestion || 'cubic'}</span>`;
  } else if (configTab === 'shadowtls') {
    // No share-link format exists for ShadowTLS: the profile carries it.
    link = location.origin + '/sub-singbox/' + u.uuid;
    label = 'sing-box subscription (ShadowTLS is inside)';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#b2bec3">ShadowTLS v3 + Shadowsocks-2022</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.shadowtls_port || 8445}</span>
      <span class="ck">Handshake</span><span class="cv">${esc(serverInfo.shadowtls_sni || '')}</span>
      <span class="ck">Import in</span><span class="cv">Hiddify, NekoBox, sing-box — or the Clash link below (Clash Meta / mihomo)</span>`;
  } else if (configTab === 'mieru') {
    link = u.mieru || '';
    label = 'Mieru Link';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#a29bfe">Mieru</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.mieru_port || 8446}</span>
      <span class="ck">Transport</span><span class="cv">${esc(serverInfo.mieru_transport || 'TCP')}</span>
      <span class="ck">Import in</span><span class="cv">mieru (mieru import config), or the Clash link below</span>`;
  } else if (configTab === 'naiveproxy') {
    // Without a publicly trusted certificate Naive runs on its own one,
    // which only the sing-box profile can carry.
    link = u.naiveproxy || (location.origin + '/sub-singbox/' + u.uuid);
    label = u.naiveproxy ? 'NaiveProxy Link' : 'sing-box subscription (NaiveProxy is inside)';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#fdcb6e">NaiveProxy</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.naiveproxy_port || 8447}</span>
      <span class="ck">TLS</span><span class="cv">Chrome TLS Fingerprint</span>`;
  } else if (configTab === 'wireguard') {
    link = u.wireguard || '';
    label = 'WireGuard Config';
    info = `
      <span class="ck">Protocol</span><span class="cv" style="color:#00b894">WireGuard</span>
      <span class="ck">Server</span><span class="cv">${SERVER_INFO.ip}</span>
      <span class="ck">Port</span><span class="cv">${serverInfo.wireguard_port || 51821}</span>
      <span class="ck">Import in</span><span class="cv">WireGuard app (scan the QR or import the file)</span>`;
  }

  // Append host header spoofing info if active. Every serverInfo.* field
  // below is operator-controlled (lives in the settings table) so it can
  // contain arbitrary text — esc() it because the result is innerHTML'd
  // below at line ~1283. Even with nonce-only script CSP, unescaped HTML
  // here would still create admin-controlled markup in a privileged screen.
  if (serverInfo.dpi_http_host_spoof_enabled) {
    info += `\n<span class="ck" style="color:var(--purple)">Host Spoof</span><span class="cv" style="color:var(--purple)">HTTP → ${esc(serverInfo.dpi_http_host_spoof_domain) || '?'}</span>`;
  }
  if (serverInfo.dpi_ws_host_front_enabled) {
    info += `\n<span class="ck" style="color:var(--purple)">WS Front</span><span class="cv" style="color:var(--purple)">→ ${esc(serverInfo.dpi_ws_host_front_domain) || '?'}</span>`;
  }
  if (serverInfo.dpi_cdn_host_front_enabled) {
    info += `\n<span class="ck" style="color:var(--purple)">CDN Front</span><span class="cv" style="color:var(--purple)">→ ${esc(serverInfo.dpi_cdn_host_front_domain) || '?'}</span>`;
  }
  if (serverInfo.dpi_bug_host_enabled) {
    info += `\n<span class="ck" style="color:var(--purple)">Bug Host</span><span class="cv" style="color:var(--purple)">→ ${esc(serverInfo.dpi_bug_host_domain) || '?'}</span>`;
  }
  // Domain / CDN Fronting
  if (serverInfo.dpi_domain_front) {
    info += `\n<span class="ck" style="color:var(--orange)">Domain Front</span><span class="cv" style="color:var(--orange)">Active — CDN hides real destination</span>`;
  }
  if (serverInfo.dpi_cdn_front_enabled) {
    info += `\n<span class="ck" style="color:var(--orange)">CDN Front</span><span class="cv" style="color:var(--orange)">Active — Cloudflare/CDN fronting</span>`;
  }
  if (serverInfo.emergency_relay_enabled && serverInfo.emergency_relay_address) {
    info += `\n<span class="ck" style="color:var(--red)">EMERGENCY RELAY</span><span class="cv" style="color:var(--red)">ACTIVE → ${esc(serverInfo.emergency_relay_address)}</span>`;
  }

  document.getElementById('config-link-label').textContent = label;
  document.getElementById('config-vmess').value = link;
  document.getElementById('config-info').innerHTML = info;

  try {
    if (link) {
      const qr = qrcode(0, 'M');
      qr.addData(link);
      qr.make();
      document.getElementById('config-qr').innerHTML = qr.createSvgTag(5, 0);
    } else {
      document.getElementById('config-qr').innerHTML = '<small style="color:var(--t3)">Not configured</small>';
    }
  } catch(e) { document.getElementById('config-qr').innerHTML = '<small style="color:var(--t3)">QR Error</small>'; }
}

function _copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0';
  document.body.appendChild(ta); ta.focus(); ta.select();
  try { document.execCommand('copy'); } catch(e) {}
  document.body.removeChild(ta);
  return Promise.resolve();
}

function copyConfigLink() {
  const ta = document.getElementById('config-vmess');
  if (!ta.value) { toast('No link available','error'); return; }
  _copyText(ta.value).then(()=>toast('Link copied')).catch(()=>toast('Link copied'));
}

function copySubUrl(id) {
  const v = document.getElementById(id || 'config-sub-url').value;
  if (!v) return;
  _copyText(v).then(()=>toast('Sub link copied')).catch(()=>toast('Sub link copied'));
}

async function forceSync() {
  const r = await fetch(API+'/sync', {method:'POST'});
  const d = await r.json();
  if (d.ok) {
    toast('Sync complete' + (d.disabled > 0 ? ' — '+d.disabled+' user(s) disabled' : ''));
    fetchUsers();
  }
  // Also sync Xray server config
  try { await fetch(API+'/xray/sync', {method:'POST'}); } catch(e) {}
}

/* ── Activity Monitor ── */
let activityTarget = '';
let activityInterval = null;
let activityTab = 'sites';

async function showActivity(name) {
  activityTarget = name;
  document.getElementById('activity-name').textContent = name;
  document.getElementById('activity-analysis').innerHTML = '<div class="activity-empty">Loading analysis...</div>';
  document.getElementById('activity-sites').innerHTML = '';
  document.getElementById('activity-recent').innerHTML = '';
  document.getElementById('activity-total').textContent = '';
  activityTab = 'analysis';
  document.querySelectorAll('.activity-tab').forEach((t,i) => t.classList.toggle('active', i===0));
  document.getElementById('activity-analysis').style.display = '';
  document.getElementById('activity-sites').style.display = 'none';
  document.getElementById('activity-recent').style.display = 'none';
  showModal('activity-modal');
  await fetchActivity();
  if (activityInterval) clearInterval(activityInterval);
  activityInterval = setInterval(fetchActivity, 5000);
}

function closeActivity() {
  closeModal('activity-modal');
  if (activityInterval) { clearInterval(activityInterval); activityInterval = null; }
}

function switchActivityTab(tab) {
  activityTab = tab;
  const tabs = ['analysis','sites','recent'];
  document.querySelectorAll('.activity-tab').forEach((t,i) =>
    t.classList.toggle('active', tabs[i]===tab));
  tabs.forEach(t => {
    const el = document.getElementById('activity-'+t);
    if (el) el.style.display = t===tab?'':'none';
  });
}

async function fetchActivity() {
  try {
    const r = await fetch(API+'/users/'+encodeURIComponent(activityTarget)+'/activity');
    if (!r.ok) return;
    renderActivity(await r.json());
  } catch(e) {}
}

function countryFlag(cc) {
  if (!cc || cc.length !== 2) return '';
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}
function isDanger(cc) { return cc === 'IL' || cc === 'PS'; }

function riskBadge(risk) {
  if (risk === 'danger') return '<span class="svc-risk-tag risk-danger">SUSPICIOUS</span>';
  if (risk === 'watch') return '<span class="svc-risk-tag risk-watch">MONITOR</span>';
  return '';
}

function renderAnalysis(analysis) {
  const el = document.getElementById('activity-analysis');
  if (!analysis || !analysis.categories || !analysis.categories.length) {
    el.innerHTML = '<div class="activity-empty">No analysis data yet.</div>';
    return;
  }
  const summary = analysis.summary || [];
  const cats = analysis.categories || [];
  const svcs = analysis.services || [];

  let html = '';
  if (summary.length) {
    html += '<div class="analysis-section"><div class="analysis-title"><span class="at-icon">\uD83D\uDD0E</span> What is this user doing?</div>';
    html += '<div class="behavior-summary">';
    summary.forEach(line => {
      const hasSusp = line.includes('[SUSPICIOUS]');
      const hasMon = line.includes('[MONITOR]');
      const clean = line.replace(' [SUSPICIOUS]','').replace(' [MONITOR]','');
      html += `<div class="behavior-line"><span class="bl-icon">${clean.charAt(0)===' '?'':clean.split(' ')[0]}</span>`;
      html += `<span>${esc(clean.substring(clean.indexOf(' ')+1))}</span>`;
      if (hasSusp) html += '<span class="bl-risk risk-danger">SUSPICIOUS</span>';
      else if (hasMon) html += '<span class="bl-risk risk-watch">MONITOR</span>';
      html += '</div>';
    });
    html += '</div></div>';
  }

  html += '<div class="analysis-section"><div class="analysis-title"><span class="at-icon">\uD83D\uDCCA</span> Traffic Breakdown</div>';
  cats.forEach(c => {
    html += `<div class="cat-bar-wrap">
      <div class="cat-bar-header">
        <span class="cat-bar-name"><span class="cb-icon">${c.icon||''}</span> ${esc(c.label)} ${riskBadge(c.risk)}</span>
        <span class="cat-bar-pct" style="color:${c.color}">${c.percent}%</span>
      </div>
      <div class="cat-bar-track"><div class="cat-bar-fill" style="width:${c.percent}%;background:${c.color}"></div></div>
      <div class="cat-bar-services">`;
    (c.top_services||[]).forEach(s => {
      html += `<span class="cat-svc-chip">${esc(s.name)} (${s.count})</span>`;
    });
    html += '</div></div>';
  });
  html += '</div>';

  html += '<div class="analysis-section"><div class="analysis-title"><span class="at-icon">\uD83C\uDFAF</span> Top Services</div>';
  html += '<div class="svc-table">';
  svcs.slice(0,15).forEach((s,i) => {
    html += `<div class="svc-row">
      <span class="svc-rank">#${i+1}</span>
      <span class="svc-name">${esc(s.name)}</span>
      <span class="svc-cat" style="background:${s.color}22;color:${s.color}">${esc(s.category)}</span>
      ${riskBadge(s.risk)}
      <span class="svc-count">${s.count}x</span>
    </div>`;
  });
  html += '</div></div>';

  el.innerHTML = html;
}

function renderDeep(deep) {
  const el = document.getElementById('activity-analysis');
  if (!deep || !deep.activities) return;

  let html = el.innerHTML;

  const vClass = deep.verdict_level==='danger'?'verdict-danger':deep.verdict_level==='watch'?'verdict-watch':'verdict-safe';
  const vIcon = deep.verdict_level==='danger'?'\uD83D\uDEA8':deep.verdict_level==='watch'?'\u26A0\uFE0F':'\u2705';
  html += `<div class="deep-section">`;
  html += `<div class="verdict-box ${vClass}">${vIcon} Verdict: ${esc(deep.verdict)}</div>`;

  html += `<div class="deep-stats">
    <div class="deep-stat"><div class="deep-stat-val">${deep.total_connections}</div><div class="deep-stat-lbl">Connections</div></div>
    <div class="deep-stat"><div class="deep-stat-val">${deep.unique_destinations}</div><div class="deep-stat-lbl">Unique Destinations</div></div>
  </div>`;

  if (deep.activities && deep.activities.length) {
    html += '<div class="deep-title">\uD83D\uDD0D Detected Activities (what they are probably doing)</div>';
    deep.activities.forEach(a => {
      const icon = a.action.includes('Watch')||a.action.includes('video')?'\u25B6':
                   a.action.includes('Messag')||a.action.includes('chat')?'\u2709':
                   a.action.includes('Search')||a.action.includes('Brows')?'\uD83D\uDD0D':
                   a.action.includes('Shop')?'\uD83D\uDED2':
                   a.action.includes('Bank')||a.action.includes('Pay')?'\uD83C\uDFE6':
                   a.action.includes('News')?'\uD83D\uDCF0':
                   a.action.includes('hack')||a.action.includes('Exploit')?'\u2620':
                   a.action.includes('adult')||a.action.includes('Adult')?'\uD83D\uDEAB':
                   a.action.includes('Game')||a.action.includes('Steam')?'\uD83C\uDFAE':
                   a.action.includes('Email')||a.action.includes('mail')?'\uD83D\uDCE7':
                   a.action.includes('VPN')||a.action.includes('Tor')?'\uD83D\uDEE1':
                   a.action.includes('AI')||a.action.includes('ChatGPT')||a.action.includes('Claude')?'\uD83E\uDD16':
                   '\uD83D\uDCBB';
      html += `<div class="activity-item">
        <span class="ai-icon">${icon}</span>
        <div class="ai-text">
          <span class="ai-action">${esc(a.action)}</span>
          <span class="ai-host">${esc(a.host)} :${a.port}</span>
        </div>
        <span class="ai-count">${a.count}x</span>
      </div>`;
    });
  }

  if (deep.ports && deep.ports.length) {
    html += '<div class="deep-title" style="margin-top:16px">\uD83D\uDD0C Protocol / Port Analysis</div>';
    deep.ports.forEach(p => {
      html += `<div class="port-row">
        <span class="port-num">:${p.port}</span>
        <span class="port-desc">${esc(p.description)}</span>
        <span class="port-count">${p.count}x</span>
      </div>`;
    });
  }

  if (deep.hourly && deep.hourly.length) {
    const maxH = Math.max(...deep.hourly.map(h=>h.count)) || 1;
    html += '<div class="deep-title" style="margin-top:16px">\u23F0 Activity Timeline (24h)</div>';
    html += '<div style="display:flex;align-items:flex-end;gap:2px;height:80px;padding:8px 0;border-bottom:1px solid var(--border)">';
    deep.hourly.forEach(h => {
      const pct = Math.max(h.count/maxH*100, h.count>0?3:0);
      const bg = h.count>0?'var(--accent)':'var(--bg3)';
      html += `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:2px" title="${h.hour}:00 — ${h.count} connections">
        <div style="width:100%;border-radius:3px 3px 0 0;background:${bg};min-height:1px;height:${pct}%"></div>
      </div>`;
    });
    html += '</div>';
    html += '<div style="display:flex;gap:2px;font-size:8px;color:var(--t3)">';
    deep.hourly.forEach((h,i) => {
      html += `<div style="flex:1;text-align:center">${i%3===0?h.hour:''}</div>`;
    });
    html += '</div>';
  }

  if (deep.peak_hours) {
    html += `<div style="margin-top:12px;padding:10px;background:var(--bg3);border-radius:var(--radius-sm);font-size:12px;color:var(--t2)">
      \u23F0 Peak activity hours: <b style="color:var(--t0)">${esc(deep.peak_hours)}</b>
    </div>`;
  }

  html += '</div>';
  el.innerHTML = html;
}

function svcTag(service, risk, color) {
  if (!service) return '';
  const rc = risk==='danger'?'var(--red)':risk==='watch'?'var(--yellow)':(color||'var(--t3)');
  return `<span class="site-svc" style="background:${rc}18;color:${rc}">${esc(service)}</span>`;
}

function renderActivity(data) {
  const analysisEl = document.getElementById('activity-analysis');
  const sitesEl = document.getElementById('activity-sites');
  const recentEl = document.getElementById('activity-recent');
  const totalEl = document.getElementById('activity-total');
  const alertsEl = document.getElementById('activity-alerts');

  if (!data.sites.length && !data.recent.length) {
    alertsEl.innerHTML = '';
    analysisEl.innerHTML = '<div class="activity-empty">No activity recorded yet.<br><small style="color:var(--t3)">Data will appear when user connects.</small></div>';
    sitesEl.innerHTML = '<div class="activity-empty">No activity recorded yet.</div>';
    recentEl.innerHTML = '<div class="activity-empty">No recent connections.</div>';
    totalEl.textContent = '';
    return;
  }
  const alerts = data.alerts || [];
  alertsEl.innerHTML = alerts.length ? alerts.map(a => `
    <div class="alert-banner alert-${a.level}">
      <span class="alert-icon">${a.level==='danger'?'\uD83D\uDEA8':'\u26A0\uFE0F'}</span>
      <span class="alert-text">${esc(a.msg)}</span>
      <span class="alert-count">${a.count}x</span>
    </div>`).join('') : '';

  renderAnalysis(data.analysis);
  if (data.deep) renderDeep(data.deep);

  sitesEl.innerHTML = data.sites.map(s => {
    const g = s.geo || {};
    const cc = g.cc || '';
    const rowClass = isDanger(cc) ? 'row-danger' : (s.host.includes('.gov')||s.host.includes('.mil') ? 'row-warning' : '');
    const svcLabel = s.service ? svcTag(s.service, s.risk||'safe') : '';
    return `<div class="site-row ${rowClass}">
      <span class="site-flag">${countryFlag(cc)}</span>
      <span class="site-geo">${esc(cc)}</span>
      <span class="site-host" title="${esc(g.org||'')} — ${esc([g.city,g.country].filter(Boolean).join(', '))}">${esc(s.host)}</span>
      ${svcLabel}
      <span class="site-port">:${s.port}</span>
      <span class="site-count">${s.count}x</span>
      <span class="site-time">${s.last.split(' ')[1]||''}</span>
    </div>`;
  }).join('');

  recentEl.innerHTML = data.recent.map(r => {
    const g = r.geo || {};
    const cc = g.cc || '';
    const svcLabel = r.service ? `<span class="recent-svc" style="background:var(--bg4);color:var(--t2)">${esc(r.service)}</span>` : '';
    return `<div class="recent-row ${isDanger(cc)?'row-danger':''}">
      <span class="recent-time">${r.time.split(' ')[1]||''}</span>
      <span class="recent-flag">${countryFlag(cc)}</span>
      <span class="recent-geo">${esc(cc)}</span>
      <span class="recent-host">${esc(r.host)}</span>
      ${svcLabel}
      <span class="recent-port">:${r.port}</span>
    </div>`;
  }).join('');

  const countries = {};
  data.sites.forEach(s => { const cc = (s.geo||{}).cc; if (cc) countries[cc] = (countries[cc]||0) + s.count; });
  const countryStr = Object.entries(countries).sort((a,b) => b[1]-a[1]).slice(0, 8)
    .map(([cc,n]) => `${countryFlag(cc)} ${cc}: ${n}`).join('  ');
  totalEl.innerHTML = `<div>${data.total} connections &nbsp;|&nbsp; ${countryStr}</div>`;
}

/* ── Settings ── */

function updateSettingsStatus() {
  // Update status indicators from serverInfo
  const si = serverInfo || {};
  const set = (id, on, label) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = 's-indicator ' + (on ? 'on' : 'off');
    const txt = el.querySelector('.si-text');
    if (txt) txt.textContent = label;
    else el.lastChild.textContent = ' ' + label;
  };
  set('si-vmess', true, 'Active :' + (si.vmess_port || 443));
  // server-info sends the REALITY public key as vless_public_key.
  const realityKey = si.vless_public_key || si.reality_public_key;
  set('si-vless', realityKey, realityKey ? 'Active :' + (si.vless_port || 2053) : 'OFF — Keys needed');
  set('si-trojan', si.trojan_enabled, si.trojan_enabled ? 'Active :' + (si.trojan_port || 2083) : 'OFF');
  set('si-grpc', si.grpc_enabled, si.grpc_enabled ? 'Active :' + (si.grpc_port || 2054) : 'OFF');
  set('si-hu', si.httpupgrade_enabled, si.httpupgrade_enabled ? 'Active :' + (si.httpupgrade_port || 2055) : 'OFF');
  set('si-ss2022', si.ss2022_enabled, si.ss2022_enabled ? 'Active :' + (si.ss2022_port || 2056) : 'OFF');
  set('si-vless-ws', si.vless_ws_enabled, si.vless_ws_enabled ? 'Active :' + (si.vless_ws_port || 2057) : 'OFF');
  set('si-vless-xhttp', si.vless_xhttp_enabled, si.vless_xhttp_enabled ? 'Active :' + (si.vless_xhttp_port || 2053) : 'OFF');
  set('si-vless-vision', si.vless_vision_enabled, si.vless_vision_enabled ? 'Active :' + (si.vless_vision_port || 2058) : 'OFF');
  set('si-vless-reverse', si.vless_reverse_enabled, si.vless_reverse_enabled ? 'Active :' + (si.vless_reverse_port || 2059) : 'OFF');
  set('si-trojan-cdn', si.trojan_cdn_enabled, si.trojan_cdn_enabled ? 'Active :' + (si.trojan_cdn_port || 2083) : 'OFF');
  set('si-hysteria2', si.hysteria2_enabled, si.hysteria2_enabled ? 'Active :' + (si.hysteria2_port || 8443) : 'OFF');
  set('si-tuic', si.tuic_enabled, si.tuic_enabled ? 'Active :' + (si.tuic_port || 8444) : 'OFF');
  set('si-amneziawg', si.amneziawg_enabled, si.amneziawg_enabled ? 'Active :' + (si.amneziawg_port || 51820) : 'OFF');
  set('si-shadowtls', si.shadowtls_enabled, si.shadowtls_enabled ? 'Active :' + (si.shadowtls_port || 8445) : 'OFF');
  set('si-mieru', si.mieru_enabled, si.mieru_enabled ? 'Active :' + (si.mieru_port || 8446) : 'OFF');
  set('si-naiveproxy', si.naiveproxy_enabled, si.naiveproxy_enabled ? 'Active :' + (si.naiveproxy_port || 8447) : 'OFF');
  set('si-wireguard', si.wireguard_enabled, si.wireguard_enabled ? 'Active :' + (si.wireguard_port || 51821) : 'OFF');
  set('si-openvpn', si.openvpn_enabled, si.openvpn_enabled ? 'Active :' + (si.openvpn_port || 1194) : 'OFF');
  set('si-cdn', si.cdn_enabled, si.cdn_enabled ? 'Active — ' + (si.cdn_domain || '?') : 'OFF');
  const killSwitchOn = asBool(si.kill_switch);
  set('si-ks', killSwitchOn, killSwitchOn ? 'ON' : 'OFF');
  set('si-fragment', si.fragment_enabled, si.fragment_enabled ? 'ON (client)' : 'OFF');
  set('si-mux', si.mux_enabled, si.mux_enabled ? 'ON (client)' : 'OFF');
  // DPI Evasion (server-side)
  const dpiRealOn = si.dpi_tcp_fragment || si.dpi_tls_fragment || si.dpi_ip_fragment || si.dpi_tcp_keepalive;
  set('si-dpi-real', dpiRealOn, dpiRealOn ? 'Active' : 'OFF');
  // Host Spoofing
  const hostSpoofOn = si.dpi_http_host_spoof_enabled || si.dpi_ws_host_front_enabled || si.dpi_cdn_host_front_enabled || si.dpi_bug_host_enabled;
  set('si-host-spoof', hostSpoofOn, hostSpoofOn ? 'Active' : 'OFF');
  // Tunneling (DNS/ICMP)
  // Obfuscation (Domain/CDN Front)
  const obfuscateOn = si.dpi_domain_front || si.dpi_cdn_front_enabled;
  set('si-dpi-obfuscate', obfuscateOn, obfuscateOn ? 'Active' : 'OFF');
  // Network resilience is always info
  const aEl = document.getElementById('si-anti');
  if (aEl) { aEl.className = 's-indicator info'; }
  const bEl = document.getElementById('si-backup');
  if (bEl) { bEl.className = 's-indicator info'; }
  // Telegram
  const tgEnabled = si.telegram_enabled || false;
  set('si-telegram', tgEnabled, tgEnabled ? 'ON' : 'OFF');
}

async function loadSettings() {
  if (_settingsLoading) return _settingsLoading;
  _settingsLoading = (async () => {
    const r = await fetch(API+'/settings');
    if (!r.ok) throw new Error('Failed to load settings');
    const s = await r.json();
    _settingsCache = s || {};
    // Config customization
    document.getElementById('set-config-prefix').value = s.config_prefix || 'Proxy';
    document.getElementById('set-vmess-port').value = s.vmess_port || 443;
    document.getElementById('set-vmess-sni').value = s.vmess_sni || 'www.aparat.com';
    document.getElementById('set-vmess-ws-path').value = s.vmess_ws_path || '/api/v1/stream';
    // Security
    setKillSwitchCheckboxes(asBool(s.kill_switch_enabled));
    // VLESS / Reality
    document.getElementById('set-reality-sni').value = s.reality_sni || 'rubika.ir';
    document.getElementById('set-vless-port').value = s.vless_port || 2053;
    document.getElementById('vless-status').textContent = s.reality_public_key
      ? 'Active — Key: ' + s.reality_public_key.substring(0, 16) + '...'
      : 'Not configured — click Regenerate Keys';
    // Trojan
    document.getElementById('set-trojan').checked = s.trojan_enabled || false;
    document.getElementById('set-trojan-port').value = s.trojan_port || 2083;
    // gRPC
    document.getElementById('set-grpc').checked = s.grpc_enabled || false;
    document.getElementById('set-grpc-port').value = s.grpc_port || 2054;
    document.getElementById('set-grpc-service').value = s.grpc_service_name || 'GunService';
    // HTTPUpgrade
    document.getElementById('set-httpupgrade').checked = s.httpupgrade_enabled || false;
    document.getElementById('set-httpupgrade-port').value = s.httpupgrade_port || 2055;
    document.getElementById('set-httpupgrade-path').value = s.httpupgrade_path || '/httpupgrade';
    // Fragment
    document.getElementById('set-fragment').checked = s.fragment_enabled || false;
    document.getElementById('set-fragment-packets').value = s.fragment_packets || 'tlshello';
    document.getElementById('set-fragment-length').value = s.fragment_length || '100-200';
    document.getElementById('set-fragment-interval').value = s.fragment_interval || '10-20';
    // MUX
    document.getElementById('set-mux').checked = s.mux_enabled || false;
    document.getElementById('set-mux-concurrency').value = s.mux_concurrency || 8;
    // SS2022
    document.getElementById('set-ss2022').checked = s.ss2022_enabled || false;
    document.getElementById('set-ss2022-port').value = s.ss2022_port || 2056;
    document.getElementById('set-ss2022-method').value = s.ss2022_method || '2022-blake3-aes-128-gcm';
    document.getElementById('set-ss2022-key').value = s.ss2022_server_key || '';
    document.getElementById('ss2022-status').textContent = s.ss2022_server_key ? 'Key active' : 'No key — click Generate';
    // VLESS WS
    document.getElementById('set-vless-ws').checked = s.vless_ws_enabled || false;
    document.getElementById('set-vless-ws-port').value = s.vless_ws_port || 2057;
    document.getElementById('set-vless-ws-path').value = s.vless_ws_path || '/vless-ws';
    // VLESS XHTTP Reality
    document.getElementById('set-vless-xhttp').checked = s.vless_xhttp_enabled || false;
    document.getElementById('set-vless-xhttp-port').value = s.vless_xhttp_port || 2053;
    document.getElementById('set-vless-xhttp-reality-sni').value = s.vless_xhttp_reality_sni || 'digikala.com';
    document.getElementById('set-vless-xhttp-reality-dest').value = s.vless_xhttp_reality_dest || 'digikala.com:443';
    document.getElementById('set-vless-xhttp-path').value = s.vless_xhttp_path || '/xhttp-stream';
    document.getElementById('set-vless-xhttp-mode').value = s.vless_xhttp_mode || 'auto';
    document.getElementById('set-vless-xhttp-reality-short-id').value = s.vless_xhttp_reality_short_id || '';
    document.getElementById('set-vless-xhttp-reality-public-key').value = s.vless_xhttp_reality_public_key || '';
    // VLESS Vision Reality
    document.getElementById('set-vless-vision').checked = s.vless_vision_enabled || false;
    document.getElementById('set-vless-vision-port').value = s.vless_vision_port || 2058;
    document.getElementById('set-vless-vision-reality-sni').value = s.vless_vision_reality_sni || 'objects.githubusercontent.com';
    document.getElementById('set-vless-vision-reality-dest').value = s.vless_vision_reality_dest || 'objects.githubusercontent.com:443';
    document.getElementById('set-vless-vision-flow').value = s.vless_vision_flow || 'xtls-rprx-vision';
    document.getElementById('set-vless-vision-reality-short-id').value = s.vless_vision_reality_short_id || '';
    document.getElementById('set-vless-vision-reality-public-key').value = s.vless_vision_reality_public_key || '';
    // VLESS Reverse Reality
    document.getElementById('set-vless-reverse').checked = s.vless_reverse_enabled || false;
    document.getElementById('set-vless-reverse-port').value = s.vless_reverse_port || 2059;
    document.getElementById('set-vless-reverse-reality-sni').value = s.vless_reverse_reality_sni || 'digikala.com';
    document.getElementById('set-vless-reverse-reality-dest').value = s.vless_reverse_reality_dest || 'digikala.com:443';
    document.getElementById('set-vless-reverse-tunnel-port').value = s.vless_reverse_tunnel_port || 0;
    document.getElementById('set-vless-reverse-backhaul-mode').value = s.vless_reverse_backhaul_mode || 'rathole';
    document.getElementById('set-vless-reverse-reality-short-id').value = s.vless_reverse_reality_short_id || '';
    document.getElementById('set-vless-reverse-reality-public-key').value = s.vless_reverse_reality_public_key || '';
    // Trojan CDN
    document.getElementById('set-trojan-cdn').checked = s.trojan_cdn_enabled || false;
    document.getElementById('set-trojan-cdn-port').value = s.trojan_cdn_port || 2083;
    document.getElementById('set-trojan-cdn-ws-path').value = s.trojan_cdn_ws_path || '/trojan-ws';
    document.getElementById('set-trojan-cdn-domain').value = s.trojan_cdn_domain || '';
    document.getElementById('set-trojan-cdn-sni').value = s.trojan_cdn_sni || '';
    document.getElementById('set-trojan-cdn-grpc').checked = s.trojan_cdn_grpc_enabled || false;
    document.getElementById('set-trojan-cdn-grpc-port').value = s.trojan_cdn_grpc_port || 2060;
    document.getElementById('set-trojan-cdn-grpc-service').value = s.trojan_cdn_grpc_service || 'TrojanService';
    // Hysteria2
    document.getElementById('set-hysteria2').checked = s.hysteria2_enabled || false;
    document.getElementById('set-hysteria2-port').value = s.hysteria2_port || 8443;
    document.getElementById('set-hysteria2-password').value = s.hysteria2_password || '';
    document.getElementById('set-hysteria2-bandwidth-up').value = s.hysteria2_bandwidth_up || '100 mbps';
    document.getElementById('set-hysteria2-bandwidth-down').value = s.hysteria2_bandwidth_down || '200 mbps';
    document.getElementById('set-hysteria2-salamander').checked = s.hysteria2_salamander_enabled || false;
    document.getElementById('set-hysteria2-salamander-password').value = s.hysteria2_salamander_password || '';
    document.getElementById('set-hysteria2-port-hop').checked = s.hysteria2_port_hop_enabled || false;
    document.getElementById('set-hysteria2-port-hop-ports').value = s.hysteria2_port_hop_ports || '20000-50000';
    // TUIC
    document.getElementById('set-tuic').checked = s.tuic_enabled || false;
    document.getElementById('set-tuic-port').value = s.tuic_port || 8444;
    document.getElementById('set-tuic-password').value = s.tuic_password || '';
    document.getElementById('set-tuic-congestion').value = s.tuic_congestion_control || 'cubic';
    document.getElementById('set-tuic-zero-rtt').checked = s.tuic_zero_rtt || false;
    // AmneziaWG
    document.getElementById('set-amneziawg').checked = s.amneziawg_enabled || false;
    document.getElementById('set-amneziawg-port').value = s.amneziawg_port || 51820;
    document.getElementById('set-amneziawg-address').value = s.amneziawg_address || '10.8.0.1/24';
    document.getElementById('set-amneziawg-dns').value = s.amneziawg_dns || '1.1.1.1';
    document.getElementById('set-amneziawg-mtu').value = s.amneziawg_mtu || 1280;
    document.getElementById('set-amneziawg-jc').value = s.amneziawg_jc ?? 4;
    document.getElementById('set-amneziawg-jmin').value = s.amneziawg_jmin ?? 50;
    document.getElementById('set-amneziawg-jmax').value = s.amneziawg_jmax ?? 1000;
    document.getElementById('set-amneziawg-s1').value = s.amneziawg_s1 ?? 0;
    document.getElementById('set-amneziawg-s2').value = s.amneziawg_s2 ?? 0;
    document.getElementById('set-amneziawg-h1').value = s.amneziawg_h1 ?? 1;
    document.getElementById('set-amneziawg-h2').value = s.amneziawg_h2 ?? 2;
    document.getElementById('set-amneziawg-h3').value = s.amneziawg_h3 ?? 3;
    document.getElementById('set-amneziawg-h4').value = s.amneziawg_h4 ?? 4;
    // ShadowTLS
    document.getElementById('set-shadowtls').checked = s.shadowtls_enabled || false;
    document.getElementById('set-shadowtls-port').value = s.shadowtls_port || 8445;
    document.getElementById('set-shadowtls-password').value = s.shadowtls_password || '';
    document.getElementById('set-shadowtls-sni').value = s.shadowtls_sni || 'rubika.ir';
    // Mieru
    document.getElementById('set-mieru').checked = s.mieru_enabled || false;
    document.getElementById('set-mieru-port').value = s.mieru_port || 8446;
    document.getElementById('set-mieru-password').value = s.mieru_password || '';
    document.getElementById('set-mieru-encryption').value = s.mieru_encryption || 'aes-256-gcm';
    document.getElementById('set-mieru-transport').value = s.mieru_transport || 'tcp';
    document.getElementById('set-mieru-mux-concurrency').value = s.mieru_mux_concurrency || 8;
    // NaiveProxy
    document.getElementById('set-naiveproxy').checked = s.naiveproxy_enabled || false;
    document.getElementById('set-naiveproxy-port').value = s.naiveproxy_port || 8447;
    document.getElementById('set-naiveproxy-user').value = s.naiveproxy_user || '';
    document.getElementById('set-naiveproxy-password').value = s.naiveproxy_password || '';
    document.getElementById('set-naiveproxy-sni').value = s.naiveproxy_sni || '';
    document.getElementById('set-naiveproxy-concurrency').value = s.naiveproxy_concurrency || 4;
    // WireGuard
    document.getElementById('set-wireguard').checked = s.wireguard_enabled || false;
    document.getElementById('set-wireguard-port').value = s.wireguard_port || 51821;
    document.getElementById('set-wireguard-address').value = s.wireguard_address || '10.9.0.1/16';
    document.getElementById('set-wireguard-dns').value = s.wireguard_dns || '1.1.1.1';
    document.getElementById('set-wireguard-mtu').value = s.wireguard_mtu || 1280;
    // OpenVPN
    document.getElementById('set-openvpn').checked = s.openvpn_enabled || false;
    document.getElementById('set-openvpn-port').value = s.openvpn_port || 1194;
    document.getElementById('set-openvpn-proto').value = s.openvpn_proto || 'udp';
    document.getElementById('set-openvpn-network').value = s.openvpn_network || '10.10.0.0/24';
    document.getElementById('set-openvpn-dns').value = s.openvpn_dns || '1.1.1.1';
    // Advanced Anti-Censorship
    document.getElementById('set-fingerprint').value = s.fingerprint || 'chrome';
    document.getElementById('set-noise').checked = s.noise_enabled || false;
    document.getElementById('set-noise-packet').value = s.noise_packet || 'rand:50-100';
    document.getElementById('set-noise-delay').value = s.noise_delay || '10-20';
    // CDN
    document.getElementById('set-cdn').checked = s.cdn_enabled;
    document.getElementById('set-cdn-domain').value = s.cdn_domain || '';
    document.getElementById('set-cdn-path').value = s.cdn_ws_path || '/cdn-ws';
    document.getElementById('set-cdn-port').value = s.cdn_port || 2082;
    // Telegram
    document.getElementById('set-telegram').checked = s.telegram_enabled || false;
    document.getElementById('set-telegram-token').value = s.telegram_bot_token || '';
    document.getElementById('set-telegram-chat').value = s.telegram_chat_id || '';
    document.getElementById('set-tg-disabled').checked = s.telegram_notify_user_disabled !== false;
    document.getElementById('set-tg-expired').checked = s.telegram_notify_user_expired !== false;
    document.getElementById('set-tg-killswitch').checked = s.telegram_notify_kill_switch !== false;
    document.getElementById('set-tg-traffic').checked = s.telegram_notify_traffic_exhausted !== false;
    document.getElementById('set-tg-created').checked = s.telegram_notify_user_created || false;
    document.getElementById('set-tg-deleted').checked = s.telegram_notify_user_deleted || false;
    // DPI Evasion (Real)
    document.getElementById('set-dpi-tcp-fragment').checked = s.dpi_tcp_fragment || false;
    document.getElementById('set-dpi-tls-fragment').checked = s.dpi_tls_fragment || false;
    document.getElementById('set-dpi-ip-fragment').checked = s.dpi_ip_fragment || false;
    document.getElementById('set-dpi-tcp-keepalive').checked = s.dpi_tcp_keepalive || false;
    document.getElementById('set-dpi-domain-front').checked = s.dpi_domain_front || false;
    document.getElementById('set-dpi-cdn-front-enabled').checked = s.dpi_cdn_front_enabled || false;
    document.getElementById('set-dpi-cdn-front').value = s.dpi_cdn_front || '';
    // Host Header Spoofing
    document.getElementById('set-dpi-http-host-spoof').checked = s.dpi_http_host_spoof_enabled || false;
    document.getElementById('set-dpi-http-host-spoof-domain').value = s.dpi_http_host_spoof_domain || 'chat.deepseek.com';
    document.getElementById('set-dpi-ws-host-front').checked = s.dpi_ws_host_front_enabled || false;
    document.getElementById('set-dpi-ws-host-front-domain').value = s.dpi_ws_host_front_domain || 'rubika.ir';
    document.getElementById('set-dpi-cdn-host-front').checked = s.dpi_cdn_host_front_enabled || false;
    document.getElementById('set-dpi-cdn-host-front-domain').value = s.dpi_cdn_host_front_domain || 'web.splus.ir';
    document.getElementById('set-dpi-bug-host').checked = s.dpi_bug_host_enabled || false;
    document.getElementById('set-dpi-bug-host-domain').value = s.dpi_bug_host_domain || 'chat.deepseek.com';
    // Advanced Network Resilience
    document.getElementById('set-dpi-packet-reorder').checked = s.dpi_packet_reorder || false;
    document.getElementById('set-dpi-dynamic-port').checked = s.dpi_dynamic_port || false;
    document.getElementById('set-dpi-fake-http').checked = s.dpi_fake_http || false;
    document.getElementById('set-dpi-traffic-shape').checked = s.dpi_traffic_shape || false;
    document.getElementById('set-dpi-multi-path').checked = s.dpi_multi_path || false;
    document.getElementById('set-dpi-protocol-hop').checked = s.dpi_protocol_hop || false;
    var aggEl = document.getElementById('set-dpi-aggression-level');
    if (aggEl) aggEl.value = s.dpi_aggression_level || 'medium';
    document.getElementById('set-emergency-relay').checked = s.emergency_relay_enabled || false;
    document.getElementById('set-emergency-relay-address').value = s.emergency_relay_address || '';
    document.getElementById('set-network-ipv6').checked = s.ipv6_enabled || false;
    var v6el = document.getElementById('detected-ipv6');
    if (v6el && s.server_ipv6) v6el.textContent = 'IPv6: ' + s.server_ipv6;
    // VLESS WS+TLS Domain Fronting
    setChk('set-vless-ws-plain-front', s.vless_ws_plain_front_enabled || false);
    setVal('set-vless-ws-plain-front-domain', s.vless_ws_plain_front_domain || 'chat.deepseek.com');
    setVal('set-vless-ws-plain-front-port', s.vless_ws_plain_front_port || 2052);
    setVal('set-vless-ws-plain-front-path', s.vless_ws_plain_front_path || '/');
    loadBackups();
    updateSettingsStatus();
    _settingsLoaded = true;
    return _settingsCache;
  })();
  try {
    return await _settingsLoading;
  } catch(e) {
    _settingsLoaded = false;
    return null;
  } finally {
    _settingsLoading = null;
  }
}

async function resetSettingsToDefault() {
  if (!await uiConfirm('Reset ALL settings to default values?\\n\\nاین کار تمام تنظیمات را به حالت پیش‌فرض برمی‌گرداند. ادامه می‌دهید؟')) return;
  // Reset all form fields in settings modal
  var defaults = {
    'set-config-prefix': 'Proxy', 'set-vmess-port': '443', 'set-vmess-sni': 'www.aparat.com', 'set-vmess-ws-path': '/api/v1/stream',
    'set-ks': false, 'set-security-ks': false,
    'set-reality-sni': 'chat.deepseek.com', 'set-vless-port': '2053',
    'set-trojan': false, 'set-trojan-port': '2083',
    'set-grpc': false, 'set-grpc-port': '2054', 'set-grpc-service': 'GunService',
    'set-httpupgrade': false, 'set-httpupgrade-port': '2055', 'set-httpupgrade-path': '/httpupgrade',
    'set-fragment': false, 'set-fragment-packets': 'tlshello', 'set-fragment-length': '100-200', 'set-fragment-interval': '10-20',
    'set-mux': false, 'set-mux-concurrency': '8',
    'set-ss2022': false, 'set-ss2022-port': '2056', 'set-ss2022-method': '2022-blake3-aes-128-gcm',
    'set-vless-ws': false, 'set-vless-ws-port': '2057', 'set-vless-ws-path': '/vless-ws',
    'set-vless-xhttp': false, 'set-vless-xhttp-port': '2053', 'set-vless-xhttp-reality-sni': 'digikala.com', 'set-vless-xhttp-path': '/xhttp-stream', 'set-vless-xhttp-mode': 'auto',
    'set-vless-vision': false, 'set-vless-vision-port': '2058', 'set-vless-vision-reality-sni': 'objects.githubusercontent.com', 'set-vless-vision-flow': 'xtls-rprx-vision',
    'set-vless-reverse': false, 'set-vless-reverse-port': '2059', 'set-vless-reverse-reality-sni': 'digikala.com', 'set-vless-reverse-backhaul-mode': 'rathole',
    'set-trojan-cdn': false, 'set-trojan-cdn-port': '2083', 'set-trojan-cdn-ws-path': '/trojan-ws', 'set-trojan-cdn-grpc': false, 'set-trojan-cdn-grpc-port': '2060', 'set-trojan-cdn-grpc-service': 'TrojanService',
    'set-hysteria2': false, 'set-hysteria2-port': '8443', 'set-hysteria2-bandwidth-up': '100 mbps', 'set-hysteria2-bandwidth-down': '200 mbps', 'set-hysteria2-salamander': false, 'set-hysteria2-port-hop': false, 'set-hysteria2-port-hop-ports': '20000-50000',
    'set-tuic': false, 'set-tuic-port': '8444', 'set-tuic-congestion': 'cubic', 'set-tuic-zero-rtt': false,
    'set-amneziawg': false, 'set-amneziawg-port': '51820', 'set-amneziawg-address': '10.8.0.1/24', 'set-amneziawg-dns': '1.1.1.1', 'set-amneziawg-mtu': '1280', 'set-amneziawg-jc': '4', 'set-amneziawg-jmin': '50', 'set-amneziawg-jmax': '1000', 'set-amneziawg-s1': '0', 'set-amneziawg-s2': '0', 'set-amneziawg-h1': '1', 'set-amneziawg-h2': '2', 'set-amneziawg-h3': '3', 'set-amneziawg-h4': '4',
    'set-shadowtls': false, 'set-shadowtls-port': '8445', 'set-shadowtls-sni': 'rubika.ir',
    'set-mieru': false, 'set-mieru-port': '8446', 'set-mieru-encryption': 'aes-256-gcm', 'set-mieru-transport': 'tcp', 'set-mieru-mux-concurrency': '8',
    'set-naiveproxy': false, 'set-naiveproxy-port': '8447', 'set-naiveproxy-concurrency': '4',
    'set-wireguard': false, 'set-wireguard-port': '51821', 'set-wireguard-address': '10.9.0.1/16', 'set-wireguard-dns': '1.1.1.1', 'set-wireguard-mtu': '1280',
    'set-openvpn': false, 'set-openvpn-port': '1194', 'set-openvpn-proto': 'udp', 'set-openvpn-network': '10.10.0.0/24', 'set-openvpn-dns': '1.1.1.1',
    'set-fingerprint': 'chrome', 'set-noise': false, 'set-noise-packet': 'rand:50-100', 'set-noise-delay': '10-20',
    'set-cdn': false, 'set-cdn-domain': '', 'set-cdn-path': '/cdn-ws', 'set-cdn-port': '2082',
    'set-telegram': false, 'set-telegram-token': '', 'set-telegram-chat': '',
    'set-tg-disabled': true, 'set-tg-expired': true, 'set-tg-killswitch': true, 'set-tg-traffic': true, 'set-tg-created': false, 'set-tg-deleted': false,
    'set-dpi-tcp-fragment': false, 'set-dpi-tls-fragment': false, 'set-dpi-ip-fragment': false, 'set-dpi-tcp-keepalive': false,
    'set-dpi-domain-front': false, 'set-dpi-cdn-front-enabled': false,
    'set-emergency-relay': false, 'set-dpi-http-host-spoof': false, 'set-dpi-ws-host-front': false, 'set-dpi-cdn-host-front': false, 'set-dpi-bug-host': false,
    'set-dpi-packet-reorder': false, 'set-dpi-dynamic-port': false, 'set-dpi-fake-http': false,
    'set-dpi-traffic-shape': false, 'set-dpi-multi-path': false, 'set-dpi-protocol-hop': false,
    'set-dpi-aggression-level': 'medium',
    'set-security-blocked-countries': 'IL', 'set-security-block-adult': false, 'set-security-block-hack': true,
    'set-security-session-timeout': '1', 'set-security-login-limit': '3',
    'set-system-agents': true, 'set-system-auto-sync': true
  };
  Object.keys(defaults).forEach(function(id) {
    var el = document.getElementById(id);
    if (!el) return;
    if (el.type === 'checkbox') el.checked = defaults[id];
    else el.value = defaults[id];
  });
  toast('Settings reset to defaults. Save to apply. / تنظیمات به حالت پیش‌فرض برگشت. ذخیره کنید.');
}

async function saveSettings() {
  if (!_settingsLoaded) {
    await loadSettings();
    if (!_settingsLoaded) {
      toast('Settings are still loading. Try again in a moment.','error');
      return;
    }
  }
  const data = {
    // Config customization
    config_prefix: document.getElementById('set-config-prefix').value.trim() || 'Proxy',
    vmess_port: parseInt(document.getElementById('set-vmess-port').value) || 443,
    vmess_sni: document.getElementById('set-vmess-sni').value.trim() || 'www.aparat.com',
    vmess_ws_path: document.getElementById('set-vmess-ws-path').value.trim() || '/api/v1/stream',
    // Security
    kill_switch_enabled: getKillSwitchValue(),
    // VLESS / Reality
    reality_sni: document.getElementById('set-reality-sni').value.trim() || 'rubika.ir',
    reality_dest: (document.getElementById('set-reality-sni').value.trim() || 'rubika.ir') + ':443',
    vless_port: parseInt(document.getElementById('set-vless-port').value) || 2053,
    // Trojan
    trojan_enabled: document.getElementById('set-trojan').checked,
    trojan_port: parseInt(document.getElementById('set-trojan-port').value) || 2083,
    // gRPC
    grpc_enabled: document.getElementById('set-grpc').checked,
    grpc_port: parseInt(document.getElementById('set-grpc-port').value) || 2054,
    grpc_service_name: document.getElementById('set-grpc-service').value.trim() || 'GunService',
    // HTTPUpgrade
    httpupgrade_enabled: document.getElementById('set-httpupgrade').checked,
    httpupgrade_port: parseInt(document.getElementById('set-httpupgrade-port').value) || 2055,
    httpupgrade_path: document.getElementById('set-httpupgrade-path').value.trim() || '/httpupgrade',
    // Fragment
    fragment_enabled: document.getElementById('set-fragment').checked,
    fragment_packets: document.getElementById('set-fragment-packets').value,
    fragment_length: document.getElementById('set-fragment-length').value.trim() || '100-200',
    fragment_interval: document.getElementById('set-fragment-interval').value.trim() || '10-20',
    // MUX
    mux_enabled: document.getElementById('set-mux').checked,
    mux_concurrency: parseInt(document.getElementById('set-mux-concurrency').value) || 8,
    // SS2022
    ss2022_enabled: document.getElementById('set-ss2022').checked,
    ss2022_port: parseInt(document.getElementById('set-ss2022-port').value) || 2056,
    ss2022_method: document.getElementById('set-ss2022-method').value,
    // VLESS WS
    vless_ws_enabled: document.getElementById('set-vless-ws').checked,
    vless_ws_port: parseInt(document.getElementById('set-vless-ws-port').value) || 2057,
    vless_ws_path: document.getElementById('set-vless-ws-path').value.trim() || '/vless-ws',
    // VLESS XHTTP Reality
    vless_xhttp_enabled: document.getElementById('set-vless-xhttp').checked,
    vless_xhttp_port: parseInt(document.getElementById('set-vless-xhttp-port').value) || 2053,
    vless_xhttp_reality_sni: document.getElementById('set-vless-xhttp-reality-sni').value.trim() || 'digikala.com',
    vless_xhttp_reality_dest: document.getElementById('set-vless-xhttp-reality-dest').value.trim() || 'digikala.com:443',
    vless_xhttp_path: document.getElementById('set-vless-xhttp-path').value.trim() || '/xhttp-stream',
    vless_xhttp_mode: document.getElementById('set-vless-xhttp-mode').value,
    vless_xhttp_reality_short_id: document.getElementById('set-vless-xhttp-reality-short-id').value.trim(),
    // VLESS Vision Reality
    vless_vision_enabled: document.getElementById('set-vless-vision').checked,
    vless_vision_port: parseInt(document.getElementById('set-vless-vision-port').value) || 2058,
    vless_vision_reality_sni: document.getElementById('set-vless-vision-reality-sni').value.trim() || 'objects.githubusercontent.com',
    vless_vision_reality_dest: document.getElementById('set-vless-vision-reality-dest').value.trim() || 'objects.githubusercontent.com:443',
    vless_vision_flow: document.getElementById('set-vless-vision-flow').value.trim() || 'xtls-rprx-vision',
    vless_vision_reality_short_id: document.getElementById('set-vless-vision-reality-short-id').value.trim(),
    // VLESS Reverse Reality
    vless_reverse_enabled: document.getElementById('set-vless-reverse').checked,
    vless_reverse_port: parseInt(document.getElementById('set-vless-reverse-port').value) || 2059,
    vless_reverse_reality_sni: document.getElementById('set-vless-reverse-reality-sni').value.trim() || 'digikala.com',
    vless_reverse_reality_dest: document.getElementById('set-vless-reverse-reality-dest').value.trim() || 'digikala.com:443',
    vless_reverse_tunnel_port: parseInt(document.getElementById('set-vless-reverse-tunnel-port').value) || 0,
    vless_reverse_backhaul_mode: document.getElementById('set-vless-reverse-backhaul-mode').value,
    vless_reverse_reality_short_id: document.getElementById('set-vless-reverse-reality-short-id').value.trim(),
    // Trojan CDN
    trojan_cdn_enabled: document.getElementById('set-trojan-cdn').checked,
    trojan_cdn_port: parseInt(document.getElementById('set-trojan-cdn-port').value) || 2083,
    trojan_cdn_ws_path: document.getElementById('set-trojan-cdn-ws-path').value.trim() || '/trojan-ws',
    trojan_cdn_domain: document.getElementById('set-trojan-cdn-domain').value.trim(),
    trojan_cdn_sni: document.getElementById('set-trojan-cdn-sni').value.trim(),
    trojan_cdn_grpc_enabled: document.getElementById('set-trojan-cdn-grpc').checked,
    trojan_cdn_grpc_port: parseInt(document.getElementById('set-trojan-cdn-grpc-port').value) || 2060,
    trojan_cdn_grpc_service: document.getElementById('set-trojan-cdn-grpc-service').value.trim() || 'TrojanService',
    // Hysteria2
    hysteria2_enabled: document.getElementById('set-hysteria2').checked,
    hysteria2_port: parseInt(document.getElementById('set-hysteria2-port').value) || 8443,
    hysteria2_password: document.getElementById('set-hysteria2-password').value.trim(),
    hysteria2_bandwidth_up: document.getElementById('set-hysteria2-bandwidth-up').value.trim() || '100 mbps',
    hysteria2_bandwidth_down: document.getElementById('set-hysteria2-bandwidth-down').value.trim() || '200 mbps',
    hysteria2_salamander_enabled: document.getElementById('set-hysteria2-salamander').checked,
    hysteria2_salamander_password: document.getElementById('set-hysteria2-salamander-password').value.trim(),
    hysteria2_port_hop_enabled: document.getElementById('set-hysteria2-port-hop').checked,
    hysteria2_port_hop_ports: document.getElementById('set-hysteria2-port-hop-ports').value.trim() || '20000-50000',
    // TUIC
    tuic_enabled: document.getElementById('set-tuic').checked,
    tuic_port: parseInt(document.getElementById('set-tuic-port').value) || 8444,
    tuic_password: document.getElementById('set-tuic-password').value.trim(),
    tuic_congestion_control: document.getElementById('set-tuic-congestion').value,
    tuic_zero_rtt: document.getElementById('set-tuic-zero-rtt').checked,
    // AmneziaWG
    amneziawg_enabled: document.getElementById('set-amneziawg').checked,
    amneziawg_port: parseInt(document.getElementById('set-amneziawg-port').value) || 51820,
    amneziawg_address: document.getElementById('set-amneziawg-address').value.trim() || '10.8.0.1/24',
    amneziawg_dns: document.getElementById('set-amneziawg-dns').value.trim() || '1.1.1.1',
    amneziawg_mtu: parseInt(document.getElementById('set-amneziawg-mtu').value) || 1280,
    amneziawg_jc: parseInt(document.getElementById('set-amneziawg-jc').value) || 0,
    amneziawg_jmin: parseInt(document.getElementById('set-amneziawg-jmin').value) || 0,
    amneziawg_jmax: parseInt(document.getElementById('set-amneziawg-jmax').value) || 0,
    amneziawg_s1: parseInt(document.getElementById('set-amneziawg-s1').value) || 0,
    amneziawg_s2: parseInt(document.getElementById('set-amneziawg-s2').value) || 0,
    amneziawg_h1: parseInt(document.getElementById('set-amneziawg-h1').value) || 0,
    amneziawg_h2: parseInt(document.getElementById('set-amneziawg-h2').value) || 0,
    amneziawg_h3: parseInt(document.getElementById('set-amneziawg-h3').value) || 0,
    amneziawg_h4: parseInt(document.getElementById('set-amneziawg-h4').value) || 0,
    // ShadowTLS
    shadowtls_enabled: document.getElementById('set-shadowtls').checked,
    shadowtls_port: parseInt(document.getElementById('set-shadowtls-port').value) || 8445,
    shadowtls_password: document.getElementById('set-shadowtls-password').value.trim(),
    shadowtls_sni: document.getElementById('set-shadowtls-sni').value.trim() || 'rubika.ir',
    // Mieru
    mieru_enabled: document.getElementById('set-mieru').checked,
    mieru_port: parseInt(document.getElementById('set-mieru-port').value) || 8446,
    mieru_password: document.getElementById('set-mieru-password').value.trim(),
    mieru_encryption: document.getElementById('set-mieru-encryption').value,
    mieru_transport: document.getElementById('set-mieru-transport').value,
    mieru_mux_concurrency: parseInt(document.getElementById('set-mieru-mux-concurrency').value) || 8,
    // NaiveProxy
    naiveproxy_enabled: document.getElementById('set-naiveproxy').checked,
    naiveproxy_port: parseInt(document.getElementById('set-naiveproxy-port').value) || 8447,
    naiveproxy_user: document.getElementById('set-naiveproxy-user').value.trim(),
    naiveproxy_password: document.getElementById('set-naiveproxy-password').value.trim(),
    naiveproxy_sni: document.getElementById('set-naiveproxy-sni').value.trim(),
    naiveproxy_concurrency: parseInt(document.getElementById('set-naiveproxy-concurrency').value) || 4,
    // WireGuard
    wireguard_enabled: document.getElementById('set-wireguard').checked,
    wireguard_port: parseInt(document.getElementById('set-wireguard-port').value) || 51821,
    wireguard_address: document.getElementById('set-wireguard-address').value.trim() || '10.9.0.1/16',
    wireguard_dns: document.getElementById('set-wireguard-dns').value.trim() || '1.1.1.1',
    wireguard_mtu: parseInt(document.getElementById('set-wireguard-mtu').value) || 1280,
    // OpenVPN
    openvpn_enabled: document.getElementById('set-openvpn').checked,
    openvpn_port: parseInt(document.getElementById('set-openvpn-port').value) || 1194,
    openvpn_proto: document.getElementById('set-openvpn-proto').value,
    openvpn_network: document.getElementById('set-openvpn-network').value.trim() || '10.10.0.0/24',
    openvpn_dns: document.getElementById('set-openvpn-dns').value.trim() || '1.1.1.1',
    // Advanced
    fingerprint: document.getElementById('set-fingerprint').value,
    noise_enabled: document.getElementById('set-noise').checked,
    noise_packet: document.getElementById('set-noise-packet').value.trim() || 'rand:50-100',
    noise_delay: document.getElementById('set-noise-delay').value.trim() || '10-20',
    // CDN
    cdn_enabled: document.getElementById('set-cdn').checked,
    cdn_domain: document.getElementById('set-cdn-domain').value.trim(),
    cdn_ws_path: document.getElementById('set-cdn-path').value.trim() || '/cdn-ws',
    cdn_port: parseInt(document.getElementById('set-cdn-port').value) || 2082,
    // Telegram
    telegram_enabled: document.getElementById('set-telegram').checked,
    telegram_bot_token: document.getElementById('set-telegram-token').value.trim(),
    telegram_chat_id: document.getElementById('set-telegram-chat').value.trim(),
    telegram_notify_user_disabled: document.getElementById('set-tg-disabled').checked,
    telegram_notify_user_expired: document.getElementById('set-tg-expired').checked,
    telegram_notify_kill_switch: document.getElementById('set-tg-killswitch').checked,
    telegram_notify_traffic_exhausted: document.getElementById('set-tg-traffic').checked,
    telegram_notify_user_created: document.getElementById('set-tg-created').checked,
    telegram_notify_user_deleted: document.getElementById('set-tg-deleted').checked,
    // DPI Evasion (Real)
    dpi_tcp_fragment: document.getElementById('set-dpi-tcp-fragment').checked,
    dpi_tls_fragment: document.getElementById('set-dpi-tls-fragment').checked,
    dpi_ip_fragment: document.getElementById('set-dpi-ip-fragment').checked,
    dpi_tcp_keepalive: document.getElementById('set-dpi-tcp-keepalive').checked,
    dpi_domain_front: document.getElementById('set-dpi-domain-front').checked,
    dpi_cdn_front_enabled: document.getElementById('set-dpi-cdn-front-enabled').checked,
    dpi_cdn_front: document.getElementById('set-dpi-cdn-front').value.trim(),
    // Host Header Spoofing
    dpi_http_host_spoof_enabled: document.getElementById('set-dpi-http-host-spoof').checked,
    dpi_http_host_spoof_domain: document.getElementById('set-dpi-http-host-spoof-domain').value.trim(),
    dpi_ws_host_front_enabled: document.getElementById('set-dpi-ws-host-front').checked,
    dpi_ws_host_front_domain: document.getElementById('set-dpi-ws-host-front-domain').value.trim(),
    dpi_cdn_host_front_enabled: document.getElementById('set-dpi-cdn-host-front').checked,
    dpi_cdn_host_front_domain: document.getElementById('set-dpi-cdn-host-front-domain').value.trim(),
    dpi_bug_host_enabled: document.getElementById('set-dpi-bug-host').checked,
    dpi_bug_host_domain: document.getElementById('set-dpi-bug-host-domain').value.trim(),
    // Advanced Network Resilience
    dpi_packet_reorder: document.getElementById('set-dpi-packet-reorder')?.checked || false,
    dpi_dynamic_port: document.getElementById('set-dpi-dynamic-port')?.checked || false,
    dpi_fake_http: document.getElementById('set-dpi-fake-http')?.checked || false,
    dpi_traffic_shape: document.getElementById('set-dpi-traffic-shape')?.checked || false,
    dpi_multi_path: document.getElementById('set-dpi-multi-path')?.checked || false,
    dpi_protocol_hop: document.getElementById('set-dpi-protocol-hop')?.checked || false,
    dpi_aggression_level: document.getElementById('set-dpi-aggression-level')?.value || 'medium',
    // Emergency Relay
    emergency_relay_enabled: document.getElementById('set-emergency-relay').checked,
    emergency_relay_address: document.getElementById('set-emergency-relay-address').value.trim(),
    ipv6_enabled: document.getElementById('set-network-ipv6').checked,
    // VLESS WS Plain Domain Fronting
    vless_ws_plain_front_enabled: document.getElementById('set-vless-ws-plain-front').checked,
    vless_ws_plain_front_domain: document.getElementById('set-vless-ws-plain-front-domain').value.trim(),
    vless_ws_plain_front_port: parseInt(document.getElementById('set-vless-ws-plain-front-port').value) || 2052,
    vless_ws_plain_front_path: document.getElementById('set-vless-ws-plain-front-path').value.trim() || '/',
  };
  const r = await fetch(API+'/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
  const d = await r.json();
  if (d.ok) {
    toast('Settings saved' + (d.rebuild ? ' — server restarted' : ''));
    await fetchServerInfo();
    updateSettingsStatus();
    showSettingsValidation(data);
  } else toast(d.error||'Error','error');
}

function showSettingsValidation(data) {
  const el = document.getElementById('settings-validation');
  if (!el) return;
  const checks = [];
  const ok = (msg) => checks.push({ok:true, msg});
  const warn = (msg) => checks.push({ok:false, msg});
  // VMess always on
  ok('VMess — Active on port ' + (data.vmess_port || 443));
  // VLESS
  if (serverInfo.vless) ok('VLESS/Reality — Active on port ' + (serverInfo.vless_port || 2053));
  else warn('VLESS/Reality — OFF (click Regenerate Keys to activate / برای فعال‌سازی Regenerate Keys بزنید)');
  // Trojan
  if (data.trojan_enabled) ok('Trojan — Active on port ' + data.trojan_port);
  else warn('Trojan — OFF');
  // gRPC
  if (data.grpc_enabled) ok('gRPC — Active on port ' + data.grpc_port);
  else warn('gRPC — OFF');
  // HTTPUpgrade
  if (data.httpupgrade_enabled) ok('HTTPUpgrade — Active on port ' + data.httpupgrade_port);
  else warn('HTTPUpgrade — OFF');
  // SS2022
  if (data.ss2022_enabled && serverInfo.ss2022) ok('SS2022 — Active on port ' + data.ss2022_port);
  else if (data.ss2022_enabled) warn('SS2022 — Enabled but no server key! Click Generate / فعال ولی بدون کلید! Generate بزنید');
  else warn('SS2022 — OFF');
  // VLESS-WS
  if (data.vless_ws_enabled) ok('VLESS-WS — Active on port ' + data.vless_ws_port);
  else warn('VLESS-WS — OFF');
  if (data.vless_xhttp_enabled) ok('VLESS-XHTTP-Reality — Active on port ' + data.vless_xhttp_port);
  else warn('VLESS-XHTTP-Reality — OFF');
  if (data.vless_vision_enabled) ok('VLESS-Vision-Reality — Active on port ' + data.vless_vision_port);
  else warn('VLESS-Vision-Reality — OFF');
  if (data.vless_reverse_enabled) ok('VLESS-Reverse-Reality — Active on port ' + data.vless_reverse_port);
  else warn('VLESS-Reverse-Reality — OFF');
  if (data.trojan_cdn_enabled) ok('Trojan-CDN — Active on port ' + data.trojan_cdn_port);
  else warn('Trojan-CDN — OFF');
  if (data.hysteria2_enabled) ok('Hysteria2 — Active on port ' + data.hysteria2_port);
  else warn('Hysteria2 — OFF');
  if (data.tuic_enabled) ok('TUIC v5 — Active on port ' + data.tuic_port);
  else warn('TUIC v5 — OFF');
  if (data.amneziawg_enabled) ok('AmneziaWG — Active on port ' + data.amneziawg_port);
  else warn('AmneziaWG — OFF');
  if (data.shadowtls_enabled) ok('ShadowTLS v3 — Active on port ' + data.shadowtls_port);
  else warn('ShadowTLS v3 — OFF');
  if (data.mieru_enabled) ok('Mieru — Active on port ' + data.mieru_port);
  else warn('Mieru — OFF');
  if (data.naiveproxy_enabled) ok('NaiveProxy — Active on port ' + data.naiveproxy_port);
  else warn('NaiveProxy — OFF');
  if (data.wireguard_enabled) ok('WireGuard — Active on port ' + data.wireguard_port);
  else warn('WireGuard — OFF');
  if (data.openvpn_enabled) ok('OpenVPN — Active on port ' + data.openvpn_port);
  else warn('OpenVPN — OFF');
  // CDN
  if (data.cdn_enabled && data.cdn_domain) ok('CDN — Active via ' + data.cdn_domain);
  else if (data.cdn_enabled) warn('CDN — Enabled but no domain set! / فعال ولی دامنه نداره!');
  else warn('CDN — OFF');
  // Fragment
  if (data.fragment_enabled) ok('Fragment — ON (' + (data.fragment_packets||'tlshello') + ')');
  else warn('Fragment — OFF');
  // MUX
  if (data.mux_enabled) ok('MUX — ON (concurrency: ' + data.mux_concurrency + ')');
  else warn('MUX — OFF');

  el.style.display = '';
  el.innerHTML = '<div style="padding:14px;background:var(--bg3);border-radius:var(--radius);border:1px solid var(--border)">' +
    '<div style="font-weight:700;margin-bottom:8px;color:var(--t1)">✅ Validation / بررسی تنظیمات:</div>' +
    checks.map(c => `<div style="font-size:12px;padding:3px 0;color:${c.ok?'#3fb950':'#f85149'}">${c.ok?'✅':'⚠️'} ${c.msg}</div>`).join('') +
    '</div>';
  setTimeout(() => { el.style.display = 'none'; }, 15000);
}

function toggleKillSwitch() {
  const source = (typeof event !== 'undefined' && event && event.target) ? event.target : null;
  if (!source) return;
  setKillSwitchCheckboxes(source.checked);
}
function toggleCDN() {}

async function regenerateReality() {
  if (!await uiConfirm('Generate new Reality keys? Existing VLESS configs will stop working.')) return;
  const r = await fetch(API+'/settings/regenerate-reality', {method:'POST'});
  const d = await r.json();
  if (d.ok) {
    toast('Reality keys regenerated — server restarted');
    document.getElementById('vless-status').textContent = 'Active — Key: ' + d.public_key.substring(0, 16) + '...';
    fetchServerInfo();
  } else toast(d.error||'Error','error');
}

async function generateSS2022Key() {
  if (!await uiConfirm('Generate new SS2022 server key? Existing SS2022 configs will need updating.')) return;
  const r = await fetch(API+'/settings/generate-ss2022-key', {method:'POST'});
  const d = await r.json();
  if (d.ok) {
    toast('SS2022 key generated — server restarted');
    document.getElementById('set-ss2022-key').value = d.ss2022_server_key;
    document.getElementById('ss2022-status').textContent = 'Key active';
    fetchServerInfo();
  } else toast(d.error||'Error','error');
}

async function doChangePw() {
  const cur = document.getElementById('pw-current').value;
  const nw = document.getElementById('pw-new').value;
  const cf = document.getElementById('pw-confirm').value;
  if (!cur) { toast('Enter current password', 'error'); return; }
  if (nw.length < 8) { toast('New password must be at least 8 characters', 'error'); return; }
  if (nw !== cf) { toast('Passwords do not match', 'error'); return; }
  const r = await fetch(API+'/change-password', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({current: cur, new: nw})
  });
  const d = await r.json();
  if (d.ok) {
    toast('Password changed. Redirecting...');
    ['pw-current','pw-new','pw-confirm'].forEach(id => document.getElementById(id).value = '');
    closeModal('pw-modal');
    setTimeout(() => location.reload(), 1500);
  } else { toast(d.error || 'Error', 'error'); }
}

/* ── Settings Tabs ── */
function switchSettingsTab(tabName) {
  // Hide all tab contents
  document.querySelectorAll('.settings-tab-content').forEach(el => el.classList.remove('active'));
  // Remove active from all tab buttons
  document.querySelectorAll('.settings-tabs .settings-tab-btn').forEach(el => el.classList.remove('active'));
  // Show selected tab content
  const content = document.getElementById('settings-' + tabName);
  if (content) content.classList.add('active');
  // Activate corresponding button
  // csp-events.js strips onclick attributes once bound, so match on data-*.
  const btn = document.querySelector('.settings-tabs .settings-tab-btn[data-settings-tab="' + tabName + '"]');
  if (btn) btn.classList.add('active');
  // Domain tab is special: when the operator opens it we
  // refresh the active-domain card and pre-fill the "set
  // domain" form. Without this the UI shows the wrong
  // issuer/expires until the user clicks Refresh manually.
  if (tabName === 'domain') {
    domainRefresh().catch(() => {});
  }
}

/* ═══════════════════════════════════════════════════════════════
   Domain & Certificate tab handlers
   ─────────────────────────────────────────────────────────────── */

let _domainLoaded = false;

async function domainRefresh() {
  try {
    const data = await apiCall(API + '/domain', { method: 'GET' });
    renderDomainStatus(data);
    setVal('set-domain-autorenew-days', data.autorenew_days || 30);
    _domainLoaded = true;
  } catch (e) { /* apiCall already toasted */ }
}

function _setLabel(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function renderDomainStatus(s) {
  const empty = document.getElementById('domain-empty');
  const active = document.getElementById('domain-active');
  const statusPill = document.getElementById('si-domain-status');
  const statusText = document.getElementById('si-domain-text');

  const cert = (s && s.cert) || {};
  const domainName = (s && (s.active_domain || s.active) || '').trim();
  if (!domainName) {
    if (empty) empty.style.display = '';
    if (active) active.style.display = 'none';
    if (statusPill) {
      statusPill.className = 's-indicator off';
      if (statusText) statusText.textContent = 'No domain';
    }
    return;
  }

  if (empty) empty.style.display = 'none';
  if (active) active.style.display = '';
  const expires = cert.expires_at || s.expires_at;
  // These are labels, not inputs. setVal() writes .value and the card stays "—".
  _setLabel('dom-active-val', domainName);
  _setLabel('dom-issuer-val', cert.issuer || s.issuer || 'unknown');
  _setLabel('dom-expires-val', expires ? new Date(expires).toLocaleDateString() : '—');
  _setLabel('dom-cert-status-val', _certStatusLabel(cert.status || s.cert_status));

  if (statusPill && statusText) {
    let cls = 'on';
    let label = 'Active';
    const certStatus = cert.status || s.cert_status;
    if (certStatus === 'expiring_soon') { cls = 'warning'; label = 'Expiring Soon'; }
    else if (certStatus === 'expired')    { cls = 'expired'; label = 'Expired'; }
    else if (certStatus === 'missing')    { cls = 'off';    label = 'No cert'; }
    else if (certStatus === 'invalid')    { cls = 'expired'; label = 'Invalid'; }
    statusPill.className = 's-indicator ' + cls;
    statusText.textContent = label;
  }

  const arText = document.getElementById('si-domain-autorenew-text');
  const arPill = document.getElementById('si-domain-autorenew');
  if (arText && arPill) {
    arPill.className = 's-indicator on';
    arText.textContent = 'Active — ' + (s.autorenew_days || 30) + 'd window';
  }
}

function _certStatusLabel(s) {
  if (s === 'ok') return '✅ Valid';
  if (s === 'expiring_soon') return '⚠️ Expiring';
  if (s === 'expired') return '❌ Expired';
  if (s === 'missing') return '— No cert';
  if (s === 'invalid') return '❌ Invalid';
  return s || '—';
}

async function domainSet() {
  const domain = (document.getElementById('set-domain-name').value || '').trim().toLowerCase();
  const email = (document.getElementById('set-domain-email').value || '').trim();
  const forceSelfSigned = document.getElementById('set-domain-self-signed').checked;
  const autorenew = parseInt(document.getElementById('set-domain-autorenew-days').value) || 30;
  if (!domain) { toast('Enter a domain', 'error'); return; }
  if (!/^[a-z0-9.-]+$/.test(domain)) {
    toast('Invalid domain format. Use lowercase letters, digits, dots, dashes only.', 'error');
    return;
  }
  const btn = event?.target;
  await withBusy(btn, async () => {
    try {
      const data = await apiCall(API + '/domain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain,
          contact_email: email,
          prefer_self_signed: forceSelfSigned,
          autorenew_days: autorenew,
        }),
      });
      const saved = !!(data && (data.ok || data.success));
      _renderDomainSetResult(Object.assign({}, data, { ok: saved }), domain);
      if (saved) {
        toast('Domain ' + domain + ' configured');
        domainRefresh();
      }
    } catch (e) { /* apiCall already toasted */ }
  });
}

function _renderDomainSetResult(d, domain) {
  const el = document.getElementById('domain-set-result');
  if (!el) return;
  el.style.display = '';
  if (!d || !d.ok) {
    el.innerHTML = `<div class="domain-result error"><b>Failed to set domain.</b><br>${esc(d?.error || 'Unknown error')}<br>${esc(d?.detail || '')}</div>`;
    return;
  }
  const steps = (d.steps || []).map(s => `<li>${esc(s)}</li>`).join('');
  const certPath = d.cert_path || '/etc/v7lthronyx/tls/' + domain + '/fullchain.pem';
  const keyPath  = d.key_path  || '/etc/v7lthronyx/tls/' + domain + '/privkey.pem';
  el.innerHTML = `
    <div class="domain-result success">
      <b>Domain set successfully / دامنه با موفقیت تنظیم شد.</b><br>
      <b>Domain:</b> ${esc(d.domain || domain)}<br>
      <b>Issuer:</b> ${esc(d.issuer || '—')}<br>
      <b>Cert Path:</b> <code>${esc(certPath)}</code><br>
      <b>Key Path:</b> <code>${esc(keyPath)}</code>
      <ul class="domain-steps">${steps}</ul>
    </div>`;
}

async function domainDisable() {
  if (!await uiConfirm('Disable the active domain? Cert files stay on disk but every TLS-bearing inbound will fall back to the server IP.')) return;
  try {
    const data = await apiCall(API + '/domain', { method: 'DELETE' });
    if (data.ok) {
      toast('Domain disabled — TLS inbounds reverted to server IP');
      domainRefresh();
    }
  } catch (e) { /* apiCall already toasted */ }
}

async function domainRenew() {
  const btn = event?.target;
  await withBusy(btn, async () => {
    try {
      const data = await apiCall(API + '/domain/renew', { method: 'POST' });
      if (data.ok) {
        toast('Certificate renewed');
        domainRefresh();
      } else {
        toast(data.error || 'Renew failed', 'error');
      }
    } catch (e) { /* apiCall already toasted */ }
  });
}

async function domainCheckOptions() {
  const btn = event?.target;
  await withBusy(btn, async () => {
    try {
      const data = await apiCall(API + '/domain/options', { method: 'GET' });
      const lines = [
        `<b>acme.sh installed:</b> ${data.acme_sh ? '✅ yes' : '❌ no'}`,
        `<b>certbot installed:</b> ${data.certbot ? '✅ yes' : '❌ no'}`,
        `<b>Port 80 free (for ACME HTTP-01):</b> ${data.port_80_free ? '✅ yes' : '❌ occupied'}`,
        `<b>Detected server IP:</b> ${data.server_ip || '?'}`,
        `<b>DNS resolves to this IP:</b> ${data.dns_resolves ? '✅ yes' : '❌ no'}`,
      ];
      const el = document.getElementById('domain-set-result');
      if (el) {
        el.style.display = '';
        const cls = (data.acme_sh || data.certbot) ? 'info' : 'error';
        el.innerHTML = `<div class="domain-result ${cls}">${lines.map(l => '<div>' + l + '</div>').join('')}</div>`;
      }
    } catch (e) { /* apiCall already toasted */ }
  });
}



/* ── Helpers ── */
// Admin screens that used to be modals are now pages. showModal() and
// closeModal() on their old ids switch pages, so every caller keeps working.
const PAGE_MODALS = {
  'settings-modal': 'settings', 'agents-modal': 'agents', 'online-modal': 'online',
  'backup-modal': 'backup', 'help-modal': 'help'
};
function showModal(id) {
  document.querySelectorAll('.modal-overlay.show').forEach(el => {
    if (el.id !== id) el.classList.remove('show');
  });
  if (PAGE_MODALS[id]) { switchOperationTab(PAGE_MODALS[id]); return; }
  const modal = document.getElementById(id);
  if (!modal) return;
  modal.classList.add('show');
  if (id === 'sysmon-modal') openSysmonDetail();
}
function applyUserPreset(gb, days) {
  const t = document.getElementById('add-traffic');
  const d = document.getElementById('add-days');
  if (t) t.value = gb;
  if (d) d.value = days;
}
function closeModal(id) {
  if (PAGE_MODALS[id]) {
    if (currentOperationTab === PAGE_MODALS[id]) switchOperationTab(previousOperationTab || 'mission');
    return;
  }
  const modal = document.getElementById(id);
  if (modal) modal.classList.remove('show');
}
function hideModal(id){closeModal(id)}
function esc(s){if(s===0)return '0';if(!s)return '';return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// Value inside a single-quoted call that csp-events.js will read back from
// the attribute. That binder only unescapes \', \" and \\ — unicode escapes
// would be passed through as literal text and the wrong user would be opened.
function jsq(s){
  return String(s==null?'':s)
    .replace(/\\/g,'\\\\')
    .replace(/'/g,"\\'")
    .replace(/"/g,'\\"')
    .replace(/[\r\n\u2028\u2029]/g,' ')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function fmtTraffic(bytes) {
  if (bytes <= 0) return '0 B';
  if (bytes < 1024) return bytes.toFixed(0) + ' B';
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
  if (bytes < 1024*1024*1024) return (bytes/(1024*1024)).toFixed(2) + ' MB';
  return (bytes/(1024*1024*1024)).toFixed(2) + ' GB';
}
function fmtBytes(b) {
  if (b < 1) return '0 B';
  const u = ['B','KB','MB','GB'];
  const i = Math.min(Math.floor(Math.log(b)/Math.log(1024)), 3);
  return (b/Math.pow(1024,i)).toFixed(i>1?2:i>0?1:0)+' '+u[i];
}
function fmtSpeed(bps) { return fmtBytes(bps)+'/s'; }

function toast(msg, type) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast show'+(type==='error'?' error':'');
  setTimeout(()=>el.className='toast', 3000);
}

/* ── Agent Management (Admin) ── */
let _agents = [];
let _agentEditId = null;
let _agentPwId = null;

async function fetchAgents() {
  try {
    const r = await fetch(API+'/agents');
    if (r.ok) _agents = await r.json();
    renderAgents();
  } catch(e) { toast('Failed to load agents', 'error'); console.error('fetchAgents failed:', e); }
}

function renderAgents() {
  const el = document.getElementById('agents-list');
  if (!el) return;
  if (!_agents.length) {
    el.innerHTML = '<div class="tactical-empty">No agents yet. Create one above; they sign in at /agent.</div>';
    return;
  }
  el.innerHTML = '<div class="ui-groups">' + _agents.map(a => {
    // The quota counts the traffic sold to users, not what they used yet.
    const quota = Number(a.traffic_quota_gb) || 0;
    const sold = Number(a.traffic_allocated_gb ?? a.traffic_used_gb) || 0;
    const used = Number(a.traffic_used_gb) || 0;
    const pct = quota > 0 ? Math.min(100, Math.round(sold / quota * 100)) : 0;
    const remaining = Math.max(0, quota - sold);
    const id = Number(a.id);
    return '<div class="ui-group">' +
      '<div class="ui-group-head">' +
        '<span class="ui-group-icon"><span class="material-symbols-outlined">support_agent</span></span>' +
        '<div class="ui-minw0" style="flex:1"><div class="ui-group-name">' + esc(a.name) + '</div>' +
        '<div class="ops-cell-sub">Signs in at /agent</div></div>' +
        (a.active ? pill('online', 'Active') : pill('muted', 'Disabled')) +
      '</div>' +
      '<div><div class="ui-quota-top"><span>' + sold.toFixed(1) + ' GB sold</span><span>/ ' + quota.toFixed(0) + ' GB</span></div>' +
      '<progress class="ops-progress ops-progress-' + quotaClass(pct) + ' ui-quota-progress" max="100" value="' + pct + '"></progress>' +
      '<div class="ui-quota-foot">' + pct + '% of quota sold · ' + used.toFixed(1) + ' GB used</div></div>' +
      '<div class="ui-group-stats">' +
        '<div><span>Remaining</span><strong>' + remaining.toFixed(1) + ' GB</strong></div>' +
        '<div><span>Users</span><strong>' + Number(a.user_count || 0) + '</strong></div>' +
      '</div>' +
      '<div class="ui-group-actions ui-row-actions">' +
        '<button type="button" class="ui-icon-btn" title="Edit quota" aria-label="Edit quota" onclick="showEditAgent(' + id + ',\'' + jsq(a.name) + '\',' + quota + ')"><span class="material-symbols-outlined">data_usage</span></button>' +
        '<button type="button" class="ui-icon-btn" title="Reset password" aria-label="Reset password" onclick="showResetAgentPw(' + id + ',\'' + jsq(a.name) + '\')"><span class="material-symbols-outlined">key</span></button>' +
        '<button type="button" class="ui-icon-btn" title="Mobile app login link" aria-label="Mobile app login link" onclick="toggleAgentAppLink(' + id + ')"><span class="material-symbols-outlined">qr_code_2</span></button>' +
        '<button type="button" class="ui-icon-btn ' + (a.active ? '' : 'is-ok') + '" title="' + (a.active ? 'Disable' : 'Enable') + '" aria-label="' + (a.active ? 'Disable' : 'Enable') + '" onclick="toggleAgent(' + id + ',' + (a.active ? 0 : 1) + ')"><span class="material-symbols-outlined">' + (a.active ? 'pause_circle' : 'play_circle') + '</span></button>' +
        '<button type="button" class="ui-icon-btn is-danger" title="Delete" aria-label="Delete" onclick="deleteAgent(' + id + ',\'' + jsq(a.name) + '\')"><span class="material-symbols-outlined">delete</span></button>' +
      '</div>' +
      '<div id="agent-app-qr-' + id + '" style="display:none;text-align:center"></div>' +
    '</div>';
  }).join('') + '</div>';
}

// Mobile-app import link (v7l://import…) — QR the admin shows the agent, or
// a link to send them. The app fills server / role / agent name from it.
const _agentAppLinks = {};
async function toggleAgentAppLink(id) {
  const box = document.getElementById('agent-app-qr-' + id);
  if (!box) return;
  if (box.style.display !== 'none') { box.style.display = 'none'; return; }
  if (!_agentAppLinks[id]) {
    try {
      const r = await fetch(API + '/agents/' + id + '/mobile-profile');
      const d = await r.json();
      _agentAppLinks[id] = d.profile_uri || '';
    } catch (e) { /* handled below */ }
  }
  const uri = _agentAppLinks[id];
  if (!uri) { toast('Failed to load app link', 'error'); return; }
  let svg = '';
  try {
    const qr = qrcode(0, 'M');
    qr.addData(uri);
    qr.make();
    svg = qr.createSvgTag(3, 0);
  } catch (e) { /* show link only */ }
  box.innerHTML =
    (svg ? `<div style="background:#fff;border-radius:10px;padding:10px;display:inline-block;margin-bottom:8px">${svg}</div>` : '') +
    `<div style="font-size:10px;color:var(--t3);word-break:break-all;margin-bottom:6px">${esc(uri)}</div>` +
    `<button class="btn btn-outline btn-sm" onclick="copyAgentAppLink(${id})">Copy link</button>`;
  box.style.display = 'block';
}

function copyAgentAppLink(id) {
  const uri = _agentAppLinks[id];
  if (!uri) { toast('Not available', 'error'); return; }
  navigator.clipboard.writeText(uri)
    .then(() => toast('Copied'))
    .catch(() => toast('Copy failed', 'error'));
}

async function doAddAgent() {
  const name = document.getElementById('agent-add-name').value.trim();
  const pass = document.getElementById('agent-add-pass').value;
  const quota = parseFloat(document.getElementById('agent-add-quota').value);
  const speed = Math.max(0, parseInt(document.getElementById('agent-add-speed').value) || 0);
  if (!name) { toast('Enter agent name','error'); return; }
  if (!pass || pass.length < 12) { toast('Password must be at least 12 characters and include upper, lower, digit, and symbol','error'); return; }
  if (!quota || quota <= 0) { toast('Enter valid quota','error'); return; }
  try {
    const d = await apiCall(API+'/agents', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name, password: pass, traffic_quota_gb: quota, speed_limit_default: speed,
        active: (document.getElementById('agent-add-active') || {checked: true}).checked})});
    if (d.ok) {
      toast('Agent '+name+' created');
      document.getElementById('agent-add-name').value = '';
      document.getElementById('agent-add-pass').value = '';
      fetchAgents();
    } else toast(d.error||'Error','error');
  } catch(e) {}
}

function showEditAgent(id, name, quota) {
  _agentEditId = id;
  document.getElementById('agent-edit-name').textContent = name;
  document.getElementById('agent-edit-quota').value = quota;
  showModal('agent-edit-modal');
}

async function doEditAgentQuota() {
  if (!_agentEditId) return;
  const quota = parseFloat(document.getElementById('agent-edit-quota').value);
  if (!quota || quota <= 0) { toast('Enter valid quota','error'); return; }
  try {
    const d = await apiCall(API+'/agents/'+_agentEditId+'/edit', {method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify({traffic_quota_gb: quota})});
    if (d.ok) { toast('Quota updated'); closeModal('agent-edit-modal'); fetchAgents(); }
    else toast(d.error||'Error','error');
  } catch(e) {}
}

function showResetAgentPw(id, name) {
  _agentPwId = id;
  document.getElementById('agent-pw-name').textContent = name;
  document.getElementById('agent-pw-new').value = '';
  showModal('agent-pw-modal');
}

async function doResetAgentPw() {
  if (!_agentPwId) return;
  const pw = document.getElementById('agent-pw-new').value;
  if (!pw || pw.length < 12) { toast('Password must be at least 12 characters and include upper, lower, digit, and symbol','error'); return; }
  try {
    const d = await apiCall(API+'/agents/'+_agentPwId+'/reset-password', {method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify({password: pw})});
    if (d.ok) { toast('Password reset'); closeModal('agent-pw-modal'); }
    else toast(d.error||'Error','error');
  } catch(e) {}
}

async function toggleAgent(id, newState) {
  try {
    const d = await apiCall(API+'/agents/'+id+'/edit', {method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({active: !!newState})});
    if (d.ok) { toast(newState?'Agent enabled':'Agent disabled'); fetchAgents(); }
    else toast(d.error||'Error','error');
  } catch(e) {}
}

async function deleteAgent(id, name) {
  if (!await uiConfirm('Delete agent "'+name+'"?\n\nTheir users will be transferred to admin.')) return;
  try {
    const d = await apiCall(API+'/agents/'+id, {method:'DELETE',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify({delete_users: false})});
    if (d.ok) { toast('Agent deleted'); fetchAgents(); }
    else toast(d.error||'Error','error');
  } catch(e) {}
}

/* ── System Monitor ── */
let sysmonData = {};

async function fetchSystemMonitor() {
  try {
    const r = await fetch(API+'/system-monitor');
    if (!r.ok) return;
    sysmonData = await r.json();
    renderSysmonBar();
  } catch(e) { console.error('fetchSystemMonitor failed:', e); }
}

function gaugeClass(pct) { return pct < 60 ? 'gauge-ok' : pct < 85 ? 'gauge-warn' : 'gauge-crit'; }

function renderSysmonBar() {
  const d = sysmonData;
  if (!d.cpu_percent && d.cpu_percent !== 0) return;
  const cpuEl = document.getElementById('sm-cpu-gauge');
  const ramEl = document.getElementById('sm-ram-gauge');
  const diskEl = document.getElementById('sm-disk-gauge');
  const upEl = document.getElementById('sm-uptime');
  const xrEl = document.getElementById('sm-xray');
  const netEl = document.getElementById('sm-net');
  if (cpuEl) { cpuEl.textContent = d.cpu_percent+'%'; cpuEl.className = 'gauge '+gaugeClass(d.cpu_percent); }
  if (ramEl) { ramEl.textContent = (d.ram_percent||0)+'%'; ramEl.className = 'gauge '+gaugeClass(d.ram_percent||0); }
  if (diskEl) { diskEl.textContent = (d.disk_percent||0)+'%'; diskEl.className = 'gauge '+gaugeClass(d.disk_percent||0); }
  if (upEl) { const s=d.uptime_seconds||0; const h=Math.floor(s/3600); const m=Math.floor((s%3600)/60); upEl.textContent = h>24 ? Math.floor(h/24)+'d '+h%24+'h' : h+'h '+m+'m'; }
  if (xrEl) xrEl.textContent = d.xray_pid ? '✅ Running' : '❌ Down';
  if (netEl) netEl.textContent = '↑'+fmtBytes(d.net_bytes_sent||0)+' ↓'+fmtBytes(d.net_bytes_recv||0);
  const rc = document.getElementById('tm-ramcpu');
  if (rc) rc.textContent = (d.ram_percent||0) + '% / ' + (d.cpu_percent||0) + '%';
  const rb = document.getElementById('tm-ram-bar');
  if (rb) {
    rb.style.width = Math.min(100, d.ram_percent||0) + '%';
    rb.className = (d.ram_percent||0) >= 85 ? 'is-bad' : ((d.ram_percent||0) >= 60 ? 'is-warn' : '');
  }
}

async function openSysmonDetail() {
  await fetchSystemMonitor();
  const d = sysmonData;
  document.getElementById('smd-cpu').textContent = (d.cpu_percent||0)+'%';
  document.getElementById('smd-ram').textContent = (d.ram_percent||0)+'%';
  document.getElementById('smd-ram-detail').textContent = fmtBytes(d.ram_used||0)+' / '+fmtBytes(d.ram_total||0);
  document.getElementById('smd-disk').textContent = (d.disk_percent||0)+'%';
  document.getElementById('smd-disk-detail').textContent = fmtBytes(d.disk_used||0)+' / '+fmtBytes(d.disk_total||0);
  document.getElementById('smd-load').textContent = (d.load_avg||[0,0,0]).map(v=>v.toFixed(2)).join(' / ');
  if (d.xray_pid) {
    document.getElementById('smd-xray').textContent = '✅ Running (PID: '+(d.xray_pid||'?')+')';
    document.getElementById('smd-xray-detail').textContent = 'Version: '+(d.xray_version||'?')+' | Mem: '+fmtBytes(d.xray_mem||0)+' | CPU: '+(d.xray_cpu||0)+'%';
  } else {
    document.getElementById('smd-xray').textContent = '❌ Not running';
    document.getElementById('smd-xray-detail').textContent = '';
  }
  document.getElementById('smd-net').textContent = '↑ Sent: '+fmtBytes(d.net_bytes_sent||0)+' | ↓ Recv: '+fmtBytes(d.net_bytes_recv||0);
  // Fetch traffic history
  fetchTrafficHistory();
  fetchTopTrafficUsers();
}

async function fetchTrafficHistory() {
  try {
    const r = await fetch(API+'/traffic-history?days=30');
    if (!r.ok) return;
    const data = await r.json();
    const chart = document.getElementById('smd-traffic-chart');
    const labels = document.getElementById('smd-traffic-labels');
    if (!data.length) { chart.innerHTML = '<div style="color:var(--t3);font-size:12px">No data yet</div>'; labels.innerHTML=''; return; }
    const maxBytes = Math.max(...data.map(d=>d.traffic_bytes||0)) || 1;
    chart.innerHTML = data.map(d => {
      const pct = Math.max(((d.traffic_bytes||0)/maxBytes)*100, d.traffic_bytes>0?3:0);
      return `<div class="traffic-chart-bar" style="height:${pct}%;background:var(--accent)" data-tip="${d.date}: ${fmtBytes(d.traffic_bytes||0)}"></div>`;
    }).join('');
    labels.innerHTML = data.map((d,i) => `<span>${i%5===0?d.date.slice(5):''}</span>`).join('');
  } catch(e) { console.error('fetchTrafficHistory failed:', e); }
}

async function fetchTopTrafficUsers() {
  try {
    const r = await fetch(API+'/traffic-history/top?days=30');
    if (!r.ok) return;
    const data = await r.json();
    const el = document.getElementById('smd-top-users');
    if (!data.length) { el.innerHTML = '<div style="color:var(--t3);font-size:12px">No data yet</div>'; return; }
    const maxB = data[0].total_bytes||1;
    el.innerHTML = data.slice(0,10).map((u,i) => {
      const pct = Math.round((u.total_bytes/maxB)*100);
      return `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="width:20px;font-size:11px;color:var(--t3);text-align:right">#${i+1}</span>
        <span style="width:80px;font-size:12px;font-weight:600;color:var(--t1);overflow:hidden;text-overflow:ellipsis">${esc(u.username)}</span>
        <div style="flex:1;height:8px;background:var(--bg4);border-radius:4px;overflow:hidden"><div style="height:100%;width:${pct}%;background:var(--accent);border-radius:4px"></div></div>
        <span style="font-size:11px;color:var(--t2);min-width:60px;text-align:right">${fmtBytes(u.total_bytes)}</span>
      </div>`;
    }).join('');
  } catch(e) { console.error('fetchTopTrafficUsers failed:', e); }
}

/* ── Online Users ── */
async function fetchOnlineUsers() {
  try {
    const r = await fetch(API+'/online-users');
    if (!r.ok) return;
    const data = await r.json();
    const el = document.getElementById('online-users-content');
    if (!data.length) {
      el.innerHTML = '<div style="color:var(--t3);text-align:center;padding:30px">No users currently online</div>';
      return;
    }
    el.innerHTML = '<div class="tactical-table-wrapper"><table class="tactical-table"><thead><tr>' +
      '<th>User</th><th>Connected from</th><th>Sessions</th><th>Moved (total)</th></tr></thead><tbody>' +
      data.map(u => `<tr>
        <td><div class="ui-user-name"><span class="online-dot on"></span>${esc(u.name || u.username)}</div></td>
        <td class="tactical-mono">${(u.ips || []).map(ip => esc(ip)).join('<br>') || '—'}</td>
        <td>${(u.ips || []).length}</td>
        <td class="tactical-mono">${fmtTraffic(u.total || 0)}</td>
      </tr>`).join('') + '</tbody></table></div>';
  } catch(e) { toast('Error fetching online users','error'); }
}

function showUserIPs(name) {
  const u = users.find(x=>x.name===name);
  if (!u || !u.online_ips || !u.online_ips.length) { toast('No IPs found','error'); return; }
  uiNotice('Connected IPs for ' + name + ':\n\n' + u.online_ips.join('\n'));
}

/* ── Add Traffic ── */
let addTrafficTarget = '';

function showAddTraffic(name) {
  addTrafficTarget = name;
  document.getElementById('addtraffic-name').textContent = name;
  document.getElementById('addtraffic-gb').value = 5;
  showModal('addtraffic-modal');
}

async function doAddTraffic() {
  const gb = parseFloat(document.getElementById('addtraffic-gb').value);
  if (!gb || gb <= 0) { toast('Enter valid GB amount','error'); return; }
  try {
    const r = await fetch(API+'/users/'+encodeURIComponent(addTrafficTarget)+'/add-traffic', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({gb})
    });
    let d = {};
    try { d = await r.json(); } catch (e) {
      toast(r.status === 404 ? 'API not found — restart panel after update' : 'Bad server response','error');
      return;
    }
    if (d.ok) {
      closeModal('addtraffic-modal');
      toast(gb+' GB added to '+addTrafficTarget);
      fetchUsers();
    } else toast(d.error||('HTTP '+r.status),'error');
  } catch(e) { toast('Connection error','error'); }
}

/* ── Edit Note ── */
async function promptEditNote(name, current) {
  const form = await uiForm({
    title: 'Note for ' + name,
    fields: [{ name: 'note', label: 'Note', value: current || '', maxlength: 200,
               hint: 'Only you see this, e.g. the customer\'s name or phone.' }],
  });
  if (!form) return;
  const note = form.note;
  try {
    const r = await fetch(API+'/users/'+encodeURIComponent(name)+'/update-note', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({note: note.trim()})
    });
    const d = await r.json();
    if (d.ok) { toast('Note updated'); fetchUsers(); }
    else toast(d.error||'Error','error');
  } catch(e) { toast('Connection error','error'); }
}

async function promptSpeed(name, currentDown, currentUp) {
  const form = await uiForm({
    title: 'Speed limit for ' + name,
    description: 'In KB/s. 0 means unlimited.',
    fields: [
      { name: 'down', label: 'Download (KB/s)', type: 'number', min: 0, value: currentDown },
      { name: 'up', label: 'Upload (KB/s)', type: 'number', min: 0, value: currentUp },
    ],
  });
  if (!form) return;
  const down = Math.max(0, parseInt(form.down, 10) || 0);
  const up = Math.max(0, parseInt(form.up, 10) || 0);
  try {
    const r = await fetch(API+'/users/'+encodeURIComponent(name)+'/speed-limit', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({speed_limit_down: down, speed_limit_up: up})
    });
    const d = await r.json();
    if (d.ok) { toast('Speed updated: ' + down + '/' + up + ' KB/s'); fetchUsers(); }
    else toast(d.error||'Error','error');
  } catch(e) { toast('Connection error','error'); }
}

/* ── Export CSV / JSON ── */
function doExportCSV() {
  window.open(API+'/export-csv', '_blank');
}

function doExportJSON() {
  window.open(API+'/export-json', '_blank');
}

/* ── Telegram Test ── */
async function testTelegram() {
  try {
    const r = await fetch(API+'/telegram-test', {method:'POST'});
    const d = await r.json();
    if (d.ok) toast('Test notification sent!');
    else toast(d.error||'Failed to send','error');
  } catch(e) { toast('Connection error','error'); }
}

/* ── Firewall Attack Functions ── */





/* ── Search Modal ── */
async function doSearch() {
  const query = document.getElementById('search-input').value.trim();
  if (!query) {
    toast('Please enter a search query', 'error');
    return;
  }

  try {
    const r = await fetch(`${API}/search?q=${encodeURIComponent(query)}`, { credentials: 'same-origin' });
    if (r.ok) {
      const data = await r.json();
      renderSearchResults(data.users);
    } else {
      toast('Search failed', 'error');
    }
  } catch(e) {
    toast('Search error', 'error');
  }
}

function renderSearchResults(results) {
  const container = document.getElementById('search-results');
  if (results.length === 0) {
    container.innerHTML = '<div class="activity-empty">No users found</div>';
    return;
  }

  container.innerHTML = results.map(u => `
    <div class="site-row">
      <div class="site-host">${u.name}</div>
      <div class="site-port">${u.active ? 'Active' : 'Inactive'}</div>
      <div class="site-count">${u.traffic_used_gb.toFixed(1)} GB</div>
      <div class="site-time">${u.expire_at ? u.expire_at.split('T')[0] : 'Never'}</div>
      <button class="btn btn-sm btn-outline" onclick="showConfig('${u.name}')">Config</button>
    </div>
  `).join('');
}

/* ── Report Modal ── */
async function loadReport() {
  try {
    const r = await fetch(`${API}/report`, { credentials: 'same-origin' });
    if (r.ok) {
      const report = await r.json();
      renderReport(report);
    } else {
      toast('Failed to load report', 'error');
    }
  } catch(e) {
    toast('Report error', 'error');
  }
}

function renderReport(report) {
  document.getElementById('report-total-users').textContent = report.total_users;
  document.getElementById('report-active-users').textContent = report.active_users;
  document.getElementById('report-inactive-users').textContent = report.inactive_users;
  document.getElementById('report-total-traffic').textContent = report.total_traffic_gb.toFixed(1) + ' GB';
  document.getElementById('report-total-limit').textContent = report.total_limit_gb.toFixed(1) + ' GB';
  document.getElementById('report-expiring-soon').textContent = report.expiring_soon;

  const topUsersContainer = document.getElementById('report-top-users');
  topUsersContainer.innerHTML = report.top_users.map(u => `
    <div class="site-row">
      <div class="site-host">${u.name}</div>
      <div class="site-count">${u.traffic_used_gb.toFixed(1)} GB</div>
      <div class="site-time">${u.active ? '✓' : '✗'}</div>
    </div>
  `).join('');
}

/* ── Analytics Modal ── */
async function loadAnalytics() {
  const days = document.getElementById('analytics-days').value || 7;
  try {
    const r = await fetch(`${API}/analytics?days=${days}`, { credentials: 'same-origin' });
    if (r.ok) {
      const analytics = await r.json();
      renderAnalytics(analytics);
    } else {
      toast('Failed to load analytics', 'error');
    }
  } catch(e) {
    toast('Analytics error', 'error');
  }
}

function renderAnalytics(analytics) {
  const dailyContainer = document.getElementById('analytics-daily');
  if (analytics.daily_traffic.length === 0) {
    dailyContainer.innerHTML = '<div class="activity-empty">No data available</div>';
  } else {
    dailyContainer.innerHTML = analytics.daily_traffic.map(d => `
      <div class="site-row">
        <div class="site-host">${d.date}</div>
        <div class="site-count">${d.total_traffic ? d.total_traffic.toFixed(1) : 0} GB</div>
        <div class="site-time">${d.user_count} users</div>
      </div>
    `).join('');
  }

  const topUsersContainer = document.getElementById('analytics-top-users');
  topUsersContainer.innerHTML = analytics.top_users.map(u => `
    <div class="site-row">
      <div class="site-host">${u.name}</div>
      <div class="site-count">${u.traffic_used_gb.toFixed(1)} GB</div>
    </div>
  `).join('');
}

/* ── Backup Modal �── */
async function loadBackups() {
  try {
    const r = await fetch(`${API}/backup/list`, { credentials: 'same-origin' });
    if (r.ok) {
      const data = await r.json();
      renderBackups(data.backups);
    } else {
      toast('Failed to load backups', 'error');
    }
  } catch(e) {
    toast('Backup list error', 'error');
  }
}

function renderBackups(backups) {
  const container = document.getElementById('backup-modal-list');
  if (backups.length === 0) {
    container.innerHTML = '<div class="activity-empty">No backups available</div>';
    return;
  }

  container.innerHTML = backups.map(b => `
    <div class="site-row">
      <div class="site-host">${b.name}</div>
      <div class="site-count">${(b.size / 1024 / 1024).toFixed(1)} MB</div>
      <div class="site-time">${b.created.split('T')[0]}</div>
      <button class="btn btn-sm btn-green" onclick="restoreBackup('${b.path}')">Restore</button>
      <button class="btn btn-sm btn-danger" onclick="deleteBackup('${b.path}')">Delete</button>
    </div>
  `).join('');
}

async function createBackup() {
  try {
    const r = await fetch(`${API}/backup/create`, { 
      method: 'POST',
      credentials: 'same-origin' 
    });
    if (r.ok) {
      toast('Backup created successfully', 'success');
      loadBackups();
    } else {
      toast('Failed to create backup', 'error');
    }
  } catch(e) {
    toast('Backup error', 'error');
  }
}

async function restoreBackup(path) {
  if (!await uiConfirm('Are you sure you want to restore this backup? This will replace current data.')) {
    return;
  }

  try {
    const r = await fetch(`${API}/backup/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ backup_path: path }),
      credentials: 'same-origin'
    });
    if (r.ok) {
      toast('Backup restored successfully', 'success');
      setTimeout(() => location.reload(), 2000);
    } else {
      toast('Failed to restore backup', 'error');
    }
  } catch(e) {
    toast('Restore error', 'error');
  }
}

async function deleteBackup(path) {
  if (!await uiConfirm('Are you sure you want to delete this backup?')) {
    return;
  }

  try {
    // Note: This would need a backend endpoint for deletion
    toast('Delete functionality not implemented', 'warning');
  } catch(e) {
    toast('Delete error', 'error');
  }
}

async function cleanupBackups() {
  const retentionDays = document.getElementById('backup-retention').value || 7;
  try {
    const r = await fetch(`${API}/backup/cleanup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ retention_days: retentionDays }),
      credentials: 'same-origin'
    });
    if (r.ok) {
      const data = await r.json();
      toast(`Cleaned up ${data.removed} old backups`, 'success');
      loadBackups();
    } else {
      toast('Cleanup failed', 'error');
    }
  } catch(e) {
    toast('Cleanup error', 'error');
  }
}









// Add event listeners for dropdown changes
document.addEventListener('DOMContentLoaded', function() {
});

/* ── Init ── */
(async function(){
  try {
    const r = await fetch(API + '/users', { credentials: 'same-origin' });
    if (r.ok) {
      document.getElementById('login-screen').style.display='none';
      document.getElementById('panel').style.display='block';
      users = await r.json(); renderUsers(); updateStats();
      startPolling();
    }
  } catch(e){}
  document.getElementById('login-pass').focus();
})();

// ═══════════════════════════════════════════════════════════════
//  SNI Auto-Select & Smart Defaults
// ═══════════════════════════════════════════════════════════════

// Safe SNI pool organized by tier (Iran 2026)
const SNI_POOL = {
  tier1_international: [
    { domain: 'objects.githubusercontent.com', label: '🌐 GitHub CDN (توصیه‌شده)', recommended: true },
    { domain: 'chat.deepseek.com', label: '🤖 DeepSeek AI' },
    { domain: 'cdn.jsdelivr.net', label: '🌐 jsDelivr CDN' },
    { domain: 'huggingface.co', label: '🤗 HuggingFace' },
    { domain: 'raw.githubusercontent.com', label: '🌐 GitHub Raw' },
    { domain: 'fonts.googleapis.com', label: '🌐 Google Fonts' },
    { domain: 'api.github.com', label: '🌐 GitHub API' },
  ],
  tier2_iran: [
    { domain: 'digikala.com', label: '🇮🇷 دیجی‌کالا (پایدارترین)', recommended_for_xhttp: true },
    { domain: 'snapp.ir', label: '🇮🇷 اسنپ' },
    { domain: 'dotic.ir', label: '🇮🇷 داتیک' },
    { domain: 'rubika.ir', label: '🇮🇷 روبیکا' },
  ],
};

// Burned SNIs that must NOT be used (Iran 2026 DPI)
const BURNED_SNIS = [
  'speedtest.net', 'www.speedtest.net',
  'microsoft.com', 'www.microsoft.com',
  'yahoo.com', 'www.yahoo.com',
  'cloudflare.com', 'www.cloudflare.com',
  'discord.com', 'www.discord.com',
  'lovelive-anime.jp',
  'apple.com', 'www.apple.com',
  'google.com', 'www.google.com',
  'bing.com', 'www.bing.com',
];

/**
 * Auto-select the best SNI for a given protocol type.
 * - xhttp: prefers Iran-domestic (same ASN = no reverse-DNS flag)
 * - vision: prefers international CDN (TLS 1.3 + H2)
 * - reverse: prefers Iran-domestic
 */
async function autoSelectBestSNI(protocolType) {
  let sniInput, destInput;

  switch (protocolType) {
    case 'xhttp':
      sniInput = document.getElementById('set-vless-xhttp-reality-sni');
      destInput = document.getElementById('set-vless-xhttp-reality-dest');
      break;
    case 'vision':
      sniInput = document.getElementById('set-vless-vision-reality-sni');
      destInput = document.getElementById('set-vless-vision-reality-dest');
      break;
    case 'reverse':
      sniInput = document.getElementById('set-vless-reverse-reality-sni');
      destInput = document.getElementById('set-vless-reverse-reality-dest');
      break;
    default:
      return;
  }

  // Try to get best SNI from DPI API
  try {
    const token = localStorage.getItem('token') || '';
    const resp = await fetch(API + '/dpi/sni/best', {
      headers: { 'Authorization': 'Bearer ' + token },
      credentials: 'same-origin',
    });
    if (resp.ok) {
      const data = await resp.json();
      if (data.sni && !BURNED_SNIS.includes(data.sni)) {
        sniInput.value = data.sni;
        destInput.value = data.sni + ':443';
        toast('🤖 بهترین SNI خودکار انتخاب شد: ' + data.sni, 'success');
        return;
      }
    }
  } catch (e) {
    // API not available, use local logic
  }

  // Fallback: local selection logic
  let bestSNI;
  if (protocolType === 'xhttp' || protocolType === 'reverse') {
    // For XHTTP/Reverse: prefer Iran-domestic (same ASN = stable)
    bestSNI = 'digikala.com';
  } else {
    // For Vision: prefer international CDN
    bestSNI = 'objects.githubusercontent.com';
  }

  sniInput.value = bestSNI;
  destInput.value = bestSNI + ':443';
  toast('🤖 بهترین SNI انتخاب شد: ' + bestSNI, 'success');
}

/**
 * Auto-fill dest field when SNI changes.
 * Appends :443 to the SNI domain.
 */
function setupSNIAutoFill() {
  const pairs = [
    ['set-vless-xhttp-reality-sni', 'set-vless-xhttp-reality-dest'],
    ['set-vless-vision-reality-sni', 'set-vless-vision-reality-dest'],
    ['set-vless-reverse-reality-sni', 'set-vless-reverse-reality-dest'],
  ];

  pairs.forEach(([sniId, destId]) => {
    const sniInput = document.getElementById(sniId);
    const destInput = document.getElementById(destId);
    if (sniInput && destInput) {
      sniInput.addEventListener('change', function() {
        const sni = this.value.trim();
        if (sni && !sni.includes(':')) {
          destInput.value = sni + ':443';
        }
      });
      sniInput.addEventListener('input', function() {
        const sni = this.value.trim();
        if (sni && !sni.includes(':')) {
          destInput.value = sni + ':443';
        }
      });
    }
  });
}

document.addEventListener('DOMContentLoaded', function() {
  setupSNIAutoFill();
});

let currentOperationTab = 'tenants';
let previousOperationTab = null;
let opsLiveTimer = null;
let _opsOverview = null;

function switchOperationTab(tabId) {
  if (tabId !== currentOperationTab) previousOperationTab = currentOperationTab;
  currentOperationTab = tabId;
  document.querySelectorAll('.ui-nav-item[data-tab]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
  });
  if (typeof closeDrawer === 'function') closeDrawer();
  window.scrollTo(0, 0);

  // Toggle a class rather than style.display: writing element.style before
  // csp-events.js has migrated the inline style attribute overwrites it.
  document.querySelectorAll('.tactical-op-view').forEach(v => {
    v.classList.toggle('active', v.id === 'op-view-' + tabId);
  });

  // Every ops tab refreshes itself while it is open.
  clearInterval(opsLiveTimer);
  opsLiveTimer = null;

  if (tabId === 'tenants') {
    if (mainView === 'groups') {
      renderGroups();
      fetchGroups();
    } else {
      renderUsers();
      fetchUsers();
    }
    return;
  }
  if (PAGE_LOADERS[tabId]) PAGE_LOADERS[tabId]();
  const refresh = OPS_TAB_REFRESH[tabId];
  if (refresh) {
    refresh[0]();
    opsLiveTimer = setInterval(refresh[0], refresh[1]);
  }
}

// Settings sections fold: the header row (title + ON/OFF pill) toggles the
// rest of the section, so the page reads as an overview. Built once; the
// first section of each tab starts open.
function initSettingsSections() {
  const root = document.getElementById('settings-modal');
  if (!root || root.dataset.sectionsReady) return;
  root.dataset.sectionsReady = '1';
  root.querySelectorAll('.settings-section').forEach(sec => {
    const head = sec.querySelector(':scope > .sec-header');
    if (!head) return;
    const body = document.createElement('div');
    body.className = 'sec-body';
    while (head.nextSibling) body.appendChild(head.nextSibling);
    sec.appendChild(body);
    sec.classList.add('is-collapsible');
    head.tabIndex = 0;
    head.setAttribute('role', 'button');
    head.setAttribute('aria-expanded', 'false');
    const chev = document.createElement('span');
    chev.className = 'material-symbols-outlined sec-chevron';
    chev.setAttribute('aria-hidden', 'true');
    chev.textContent = 'expand_more';
    head.appendChild(chev);
    const toggle = () => head.setAttribute('aria-expanded', String(sec.classList.toggle('open')));
    head.addEventListener('click', toggle);
    head.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
    });
  });
  root.querySelectorAll('.settings-tab-content').forEach(tab => {
    const first = tab.querySelector('.settings-section.is-collapsible');
    if (first) {
      first.classList.add('open');
      first.querySelector(':scope > .sec-header').setAttribute('aria-expanded', 'true');
    }
  });
}

// Admin pages (formerly modals): load once when opened.
const PAGE_LOADERS = {
  settings: () => { initSettingsSections(); loadSettings(); switchSettingsTab('protocols'); },
  agents: () => fetchAgents(),
  backup: () => loadBackups()
};

// [loader, refresh interval ms]. Protocols run network checks, so slower.
const OPS_TAB_REFRESH = {
  mission: [() => loadMissionView(), 5000],
  warroom: [() => loadWarroomView(), 15000],
  protocols: [() => loadProtocolsView(), 120000],
  nodes: [() => loadNodesView(), 60000],
  sentinel: [() => loadSentinelView(), 60000],
  routing: [() => loadRoutingView(), 60000],
  diagnostics: [() => loadCarriersView(), 60000],
  financials: [() => loadFinancialsView(), 60000],
  security: [() => loadSecurityView(), 60000],
  online: [() => fetchOnlineUsers(), 15000]
};

/* ── Ops helpers ── */
async function opsFetch(path, opts) {
  const r = await fetch(API + path, opts);
  let d = {};
  try { d = await r.json(); } catch (e) {}
  if (!r.ok) {
    const detail = Array.isArray(d.detail) ? d.detail.map(x => x.msg).join('; ') : d.detail;
    throw new Error(detail || ('HTTP ' + r.status));
  }
  return d;
}

function opsJson(method, body) {
  return { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function tableMessage(bodyId, cols, msg) {
  const body = document.getElementById(bodyId);
  if (body) body.innerHTML = '<tr><td colspan="' + cols + '" class="tactical-empty">' + esc(msg) + '</td></tr>';
}

function fmtBps(bps) {
  if (bps == null) return '—';
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
  let i = 0;
  while (bps >= 1000 && i < units.length - 1) { bps /= 1000; i++; }
  return bps.toFixed(i ? 1 : 0) + ' ' + units[i];
}

function fmtDuration(sec) {
  sec = Math.max(0, Math.floor(sec || 0));
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return d ? d + 'd ' + h + 'h' : (h ? h + 'h ' + m + 'm' : m + 'm');
}

// The API returns naive UTC timestamps.
function parseUtc(iso) {
  if (!iso) return null;
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z');
}

function fmtAgo(iso) {
  const t = parseUtc(iso);
  if (!t) return 'never';
  const s = Math.max(0, (Date.now() - t.getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

function fmtMs(v) { return v == null ? '—' : Math.round(v) + ' ms'; }
function fmtPct(rate) { return rate == null ? '—' : Math.round(rate * 100) + '%'; }
function fmtTests(n) { return n + (n === 1 ? ' test' : ' tests'); }

function okClass(rate) { return rate >= 0.8 ? 'online' : (rate >= 0.4 ? 'warning' : 'danger'); }

function pill(cls, text, title) {
  return '<span class="status-pill ' + cls + '"' + (title ? ' title="' + esc(title) + '"' : '') + '>' + esc(text) + '</span>';
}

/* ── Overview: topbar, sidebar, Mission Control, War-Room ── */
async function fetchOpsOverview() {
  const d = await opsFetch('/ops/overview');
  _opsOverview = d;
  applyOpsStatus(d);
  return d;
}

function applyOpsStatus(d) {
  const running = d.xray_running;
  setText('ops-hostname', d.host.hostname);
  setText('ops-uptime', 'Up ' + fmtDuration(d.host.uptime_seconds));
  setText('ops-proto-count', (running ? 'Operational' : 'Xray down') + ' · ' + d.protocols.enabled + ' protocols');
  const chip = document.getElementById('ops-status-chip');
  if (chip) chip.className = 'ui-chip' + (running ? '' : ' is-bad');
  const dot = document.getElementById('ops-host-dot');
  if (dot) dot.className = 'ops-dot ' + (running ? 'is-ok' : 'is-bad');
  if (d.admin) {
    setText('ops-admin-name', d.admin);
    setText('ops-admin-initial', d.admin.charAt(0));
  }

  // Core telemetry card in the sidebar
  const tm = (id, text, cls) => {
    const el = document.getElementById(id);
    if (el) { el.textContent = text; el.className = cls; }
  };
  const ver = (sysmonData && sysmonData.xray_version) ? 'v' + String(sysmonData.xray_version).replace(/^v/, '') + ' ' : '';
  tm('tm-xray', running ? ver + 'running' : 'down', running ? 'ui-tm-ok' : 'ui-tm-bad');
  const sb = d.singbox || {};
  tm('tm-singbox', !sb.needed ? 'not used' : (sb.running ? 'active' : 'down'),
     !sb.needed ? 'ui-tm-dim' : (sb.running ? 'ui-tm-ok' : 'ui-tm-bad'));
  tm('tm-redis', d.redis_ok ? 'Connected' : 'Unavailable', d.redis_ok ? 'ui-tm-ok' : 'ui-tm-bad');
  const pulse = document.getElementById('tm-dot');
  if (pulse) pulse.className = 'ui-pulse ' + (running ? 'is-ok' : 'is-bad');

  const p = d.posture;
  document.querySelectorAll('[data-cloak-label]').forEach(el => {
    el.textContent = p.cloak_active ? (p.cloak_source === 'auto' ? 'Cloak: AUTO' : 'Cloak: ON') : 'Emergency Cloak';
  });
}

function refreshOpsStatus() {
  fetchOpsOverview().catch(e => console.warn('ops overview failed:', e.message));
}

function drawSpark(id, values) {
  const svg = document.getElementById(id);
  if (!svg) return;
  if (values.length < 2) { svg.innerHTML = ''; return; }
  const max = Math.max(1, ...values);
  const step = 240 / (values.length - 1);
  const pts = values.map((v, i) => (i * step).toFixed(1) + ' ' + (46 - v / max * 42).toFixed(1));
  const line = 'M' + pts.join(' L');
  svg.innerHTML = '<path class="ops-spark-area" d="' + line + ' L240 48 L0 48 Z"></path>' +
    '<path class="ops-spark-line" d="' + line + '"></path>';
}

async function loadMissionView() {
  try {
    const d = await fetchOpsOverview();
    const net = d.network;
    setText('mc-in', net.in_bps == null ? 'sampling…' : fmtBps(net.in_bps));
    setText('mc-out', net.out_bps == null ? 'sampling…' : fmtBps(net.out_bps));
    drawSpark('mc-in-spark', net.history.map(h => h.in_bps));
    drawSpark('mc-out-spark', net.history.map(h => h.out_bps));
    setText('mc-online', d.users.online);
    setText('mc-users', d.users.active + ' active of ' + d.users.total + ' users');
    setText('mc-protocols', d.protocols.enabled + ' / ' + d.protocols.total);
    setText('mc-uptime', 'Server up ' + fmtDuration(d.host.uptime_seconds));
    const x = document.getElementById('mc-xray');
    if (x) {
      x.textContent = d.xray_running ? 'XRAY RUNNING' : 'XRAY DOWN';
      x.className = 'status-pill ' + (d.xray_running ? 'online' : 'danger');
    }
  } catch (e) {
    setText('mc-in', '—');
    setText('mc-out', '—');
    console.warn('mission control failed:', e.message);
  }
}

const OPS_EVENT_LABELS = {
  honeypot_hit: ['HONEYPOT', 'red'],
  login_failed: ['LOGIN FAILED', 'yellow'],
  login_2fa_failed: ['2FA FAILED', 'yellow'],
  login: ['LOGIN', 'green'],
  panic_flush: ['PANIC FLUSH', 'accent'],
  emergency_cloak_on: ['CLOAK ON', 'accent'],
  emergency_cloak_off: ['CLOAK OFF', 'accent'],
  probe_created: ['PROBE ADDED', 'accent'],
  probe_deleted: ['PROBE REMOVED', 'accent'],
  edge_node_added: ['NODE ADDED', 'accent'],
  edge_node_deleted: ['NODE REMOVED', 'accent'],
  automation_updated: ['AUTOMATION', 'accent']
};

async function loadWarroomView() {
  const stream = document.getElementById('wr-events');
  try {
    const d = await fetchOpsOverview();
    const s = d.security_24h, p = d.posture;
    setText('wr-honeypot', s.honeypot_hits);
    setText('wr-failed', s.failed_logins);
    setText('wr-bans', s.active_bans);
    const evasions = [p.fragment, p.noise, p.mux].filter(Boolean).length;
    setText('wr-posture', p.cloak_active ? 'CLOAKED' : (evasions ? 'HARDENED' : 'DEFAULT'));
    const on = v => v ? 'on' : 'off';
    setText('wr-posture-detail', 'fragment ' + on(p.fragment) + ' · noise ' + on(p.noise) + ' · mux ' + on(p.mux) + ' · fp ' + p.fingerprint);
    if (!stream) return;
    if (!d.events.length) {
      stream.innerHTML = '<div class="tactical-empty">No security events yet.</div>';
      return;
    }
    // detail and ip come from attackers (honeypot paths, login usernames): escape everything.
    stream.innerHTML = d.events.map(ev => {
      const meta = OPS_EVENT_LABELS[ev.action] || [ev.action, 'accent'];
      const t = parseUtc(ev.at);
      return '<div class="ops-event">' +
        '<span class="ops-event-time">' + esc(t ? t.toLocaleString() : '') + '</span>' +
        '<span class="ops-event-tag ops-' + meta[1] + '">' + esc(meta[0]) + '</span>' +
        '<span class="ops-event-detail">' + esc(ev.detail) + '</span>' +
        '<span class="ops-event-ip">' + esc(ev.ip || '') + '</span>' +
      '</div>';
    }).join('');
  } catch (e) {
    if (stream) stream.innerHTML = '<div class="tactical-empty">Could not load: ' + esc(e.message) + '</div>';
  }
  loadAutomation();
}

/* ── Automation (Celery beat runs the checks every minute) ── */
async function loadAutomation() {
  try {
    applyAutomation(await opsFetch('/ops/automation'));
  } catch (e) {
    const hb = document.getElementById('auto-heartbeat');
    if (hb) { hb.textContent = 'ERROR'; hb.className = 'status-pill danger'; hb.title = e.message; }
  }
}

function applyAutomation(a) {
  document.querySelectorAll('[data-auto-key]').forEach(el => {
    el.checked = !!a.settings[el.getAttribute('data-auto-key')];
  });
  const hb = document.getElementById('auto-heartbeat');
  if (hb) {
    const last = parseUtc(a.last_run_at);
    const age = last ? (Date.now() - last.getTime()) / 1000 : null;
    if (age == null) {
      hb.textContent = 'NEVER RUN';
      hb.className = 'status-pill warning';
      hb.title = 'No automatic check has run yet. On the server, check that the Celery beat and worker services are running.';
    } else if (age > 300) {
      hb.textContent = 'STALLED · ' + fmtAgo(a.last_run_at);
      hb.className = 'status-pill warning';
      hb.title = 'The every-minute check stopped. Check the Celery beat and worker services.';
    } else {
      hb.textContent = 'RUNNING · ' + fmtAgo(a.last_run_at);
      hb.className = 'status-pill online';
      hb.title = 'Checks run every minute';
    }
  }
  setText('auto-cloak-rule', 'On when ' + a.rules.engage + '. Off when ' + a.rules.release +
    '. Never switches off a cloak you turned on; after you switch it off, waits ' + a.rules.manual_off_hold_hours + ' h.');
  setText('auto-telegram', a.telegram_configured
    ? 'Telegram configured' + (a.last_delivery_ok === false ? ' · last delivery FAILED' : '') + '. Xray, edge nodes, blocked protocols, silent probes.'
    : 'Telegram is not configured: enable it in Settings → Telegram (bot token and chat ID).');
  const log = document.getElementById('auto-log');
  if (log) {
    log.innerHTML = a.log.length ? a.log.map(e => {
      const t = parseUtc(e.at);
      return '<div class="ops-event ops-event-2">' +
        '<span class="ops-event-time">' + esc(t ? t.toLocaleString() : '') + '</span>' +
        '<span class="ops-event-detail" dir="rtl">' + esc(e.text) + '</span></div>';
    }).join('') : '<div class="tactical-empty">No automatic actions yet.</div>';
  }
}

async function setAutomation(el) {
  const key = el.getAttribute('data-auto-key');
  const body = {};
  body[key] = el.checked;
  try {
    applyAutomation(await opsFetch('/ops/automation', opsJson('POST', body)));
    toast('Saved');
  } catch (e) {
    el.checked = !el.checked;
    toast(e.message, 'error');
  }
}

async function runAutomationNow() {
  toast('Running checks…');
  try {
    const d = await opsFetch('/ops/automation/run', { method: 'POST' });
    applyAutomation(d.status);
    toast(d.events ? d.events + ' change(s) found' : 'Checked: no changes');
    refreshOpsStatus();
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function sendTestAlert() {
  try {
    await opsFetch('/ops/automation/test-alert', { method: 'POST' });
    toast('Test alert sent to Telegram');
  } catch (e) {
    toast(e.message, 'error');
  }
}

/* ── Emergency actions ── */
async function panicFlush() {
  if (!await uiConfirm('Panic Flush restarts Xray (and sing-box / Mieru if enabled).\n' +
               'Every connected user is disconnected; clients reconnect on their own.\n\nContinue?')) return;
  try {
    const d = await opsFetch('/ops/panic-flush', { method: 'POST' });
    const lines = Object.entries(d.services).map(([svc, r]) => svc + ': ' + (r.ok ? 'restarted' : 'FAILED (' + r.message + ')'));
    uiNotice((d.ok ? 'Panic Flush done.\n\n' : 'Panic Flush incomplete.\n\n') + lines.join('\n'), d.ok ? 'ok' : 'error');
  } catch (e) {
    uiNotice('Panic Flush failed: ' + e.message, 'error');
  }
  refreshOpsStatus();
}

async function toggleEmergencyCloak() {
  let current;
  try {
    current = await opsFetch('/ops/cloak');
  } catch (e) {
    toast('Cloak: ' + e.message, 'error');
    return;
  }
  const want = !current.active;
  const msg = want
    ? 'Emergency Cloak forces TLS-hello fragmentation and noise packets into every client config.\n' +
      'Your current fragment/noise settings are saved and restored when you turn it off.\n' +
      'Users get the change on their next subscription refresh.\n\nTurn Emergency Cloak ON?'
    : 'Turn Emergency Cloak OFF and restore your previous fragment/noise settings?';
  if (!await uiConfirm(msg)) return;
  try {
    const d = await opsFetch('/ops/cloak', opsJson('POST', { active: want }));
    toast(d.active ? 'Emergency Cloak ON' : 'Emergency Cloak OFF: previous settings restored');
  } catch (e) {
    toast('Cloak: ' + e.message, 'error');
  }
  refreshOpsStatus();
  if (currentOperationTab === 'warroom') loadWarroomView();
}

/* ── Protocol health ── */
async function loadProtocolsView() {
  fetchServerInfo();
  const pbody = document.getElementById('protocols-health-body');
  if (pbody && !pbody.querySelector('td:not(.tactical-empty)')) tableMessage('protocols-health-body', 6, 'Checking…');
  try {
    const d = await opsFetch('/ops/protocols');
    const body = document.getElementById('protocols-health-body');
    if (!d.protocols.length) {
      tableMessage('protocols-health-body', 6, 'No protocol is enabled. Use Configure to turn some on.');
    } else {
      body.innerHTML = d.protocols.map(p => {
        const listening = p.listening == null ? pill('muted', 'UNKNOWN') : (p.listening ? pill('online', 'YES') : pill('danger', 'NO'));
        let dest = '<span class="tactical-muted">—</span>';
        if (p.dest_check) {
          dest = (p.dest_check.ok ? pill('online', fmtMs(p.dest_check.ms)) : pill('danger', 'FAIL', p.dest_check.error)) +
            '<div class="ops-cell-sub">' + esc(p.dest) + (p.dest_check.ok ? '' : ' · ' + esc(p.dest_check.error)) + '</div>';
        }
        let fromIran = '<span class="tactical-muted">' + (p.transport === 'udp' ? 'not testable (UDP)' : 'no probe data') + '</span>';
        if (p.probe_24h) {
          fromIran = pill(okClass(p.probe_24h.ok_rate), fmtPct(p.probe_24h.ok_rate)) +
            '<div class="ops-cell-sub">' + fmtTests(p.probe_24h.attempts) + (p.probe_24h.median_ms != null ? ' · ' + fmtMs(p.probe_24h.median_ms) : '') + '</div>';
        }
        return '<tr>' +
          '<td><strong>' + esc(p.name) + '</strong><div class="ops-cell-sub">' + esc(p.method.toUpperCase()) + (p.sni ? ' · SNI ' + esc(p.sni) : '') + '</div></td>' +
          '<td class="tactical-mono">' + esc(String(p.port || '—')) + '/' + esc(p.transport) + '</td>' +
          '<td>' + listening + '</td>' +
          '<td>' + dest + '</td>' +
          '<td>' + fromIran + '</td>' +
          '<td>' + (p.rotation_blocked ? pill('danger', 'BLOCKED') : '<span class="tactical-muted">—</span>') + '</td>' +
        '</tr>';
      }).join('');
    }
    const note = document.getElementById('protocols-disabled');
    if (note) {
      note.hidden = !d.disabled.length;
      note.textContent = d.disabled.length ? 'Disabled: ' + d.disabled.join(', ') : '';
    }
  } catch (e) {
    tableMessage('protocols-health-body', 6, 'Could not load: ' + e.message);
  }
}

/* ── Edge nodes ── */
function renderNodes(nodes) {
  const body = document.getElementById('nodes-table-body');
  if (!body) return;
  if (!nodes.length) {
    tableMessage('nodes-table-body', 6, 'No edge nodes yet. Add your other servers above.');
    return;
  }
  body.innerHTML = nodes.map(n => {
    let status = pill('muted', 'NOT CHECKED');
    if (n.reachable === true) status = pill('online', 'REACHABLE');
    else if (n.reachable === false) status = pill('danger', 'UNREACHABLE', n.last_error) + '<div class="ops-cell-sub">' + esc(n.last_error || '') + '</div>';
    return '<tr>' +
      '<td><strong>' + esc(n.name) + '</strong>' + (n.location ? '<div class="ops-cell-sub">' + esc(n.location) + '</div>' : '') + '</td>' +
      '<td class="tactical-mono">' + esc(n.address) + ':' + Number(n.port) + '</td>' +
      '<td>' + status + '</td>' +
      '<td class="tactical-mono tactical-accent">' + fmtMs(n.rtt_ms) + '</td>' +
      '<td class="tactical-muted">' + esc(fmtAgo(n.last_checked_at)) + '</td>' +
      '<td><button type="button" class="btn btn-sm btn-outline" onclick="deleteEdgeNode(' + Number(n.id) + ')">Remove</button></td>' +
    '</tr>';
  }).join('');
}

async function loadNodesView() {
  try {
    renderNodes((await opsFetch('/ops/nodes')).nodes);
  } catch (e) {
    tableMessage('nodes-table-body', 6, 'Could not load: ' + e.message);
  }
}

async function addEdgeNode() {
  const val = id => (document.getElementById(id).value || '').trim();
  const name = val('node-name'), address = val('node-address');
  if (!name || !address) { toast('Name and address are required', 'error'); return; }
  try {
    await opsFetch('/ops/nodes', opsJson('POST', {
      name: name, address: address,
      port: parseInt(val('node-port'), 10) || 443,
      location: val('node-location') || null
    }));
    ['node-name', 'node-address', 'node-location'].forEach(id => { document.getElementById(id).value = ''; });
    toast('Node added');
    loadNodesView();
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function deleteEdgeNode(id) {
  if (!await uiConfirm('Remove this edge node?')) return;
  try {
    await opsFetch('/ops/nodes/' + Number(id), { method: 'DELETE' });
    loadNodesView();
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function checkEdgeNodes() {
  toast('Checking nodes…');
  try {
    renderNodes((await opsFetch('/ops/nodes/check', { method: 'POST' })).nodes);
  } catch (e) {
    toast(e.message, 'error');
  }
}

/* ── Sentinel probes ── */
async function loadSentinelView() {
  try {
    const d = await opsFetch('/ops/probes');
    const body = document.getElementById('sentinel-table-body');
    if (!d.probes.length) {
      tableMessage('sentinel-table-body', 7, 'No probes yet. Create a token above and run the probe inside Iran.');
      return;
    }
    body.innerHTML = d.probes.map(p => '<tr>' +
      '<td><strong>' + esc(p.name) + '</strong></td>' +
      '<td class="tactical-mono tactical-muted">' + esc(p.token_prefix) + '…</td>' +
      '<td>' + esc(p.last_carrier || '—') + '</td>' +
      '<td class="tactical-muted">' + esc(fmtAgo(p.last_seen_at)) + '</td>' +
      '<td class="tactical-mono">' + Number(p.reports_24h) + '</td>' +
      '<td>' + (p.ok_rate_24h == null ? '<span class="tactical-muted">—</span>' : pill(okClass(p.ok_rate_24h), fmtPct(p.ok_rate_24h))) + '</td>' +
      '<td><button type="button" class="btn btn-sm btn-outline" onclick="deleteProbe(' + Number(p.id) + ')">Delete</button></td>' +
    '</tr>').join('');
  } catch (e) {
    tableMessage('sentinel-table-body', 7, 'Could not load: ' + e.message);
  }
}

async function createProbe() {
  const input = document.getElementById('probe-name');
  const name = (input.value || '').trim();
  if (!name) { toast('Give the probe a name', 'error'); return; }
  try {
    const d = await opsFetch('/ops/probes', opsJson('POST', { name: name }));
    const origin = location.origin;
    document.getElementById('probe-command').textContent = [
      'curl -fsSLo spiritus-probe.py ' + origin + '/api/probe/script',
      'export SPIRITUS_PROBE_TOKEN=' + d.token,
      'python3 spiritus-probe.py --panel ' + origin + ' --interval 900'
    ].join('\n');
    document.getElementById('probe-created').hidden = false;
    input.value = '';
    loadSentinelView();
  } catch (e) {
    toast(e.message, 'error');
  }
}

function copyProbeCommand() {
  const text = document.getElementById('probe-command').textContent;
  _copyText(text).then(() => toast('Commands copied')).catch(() => toast('Copy failed', 'error'));
}

async function deleteProbe(id) {
  if (!await uiConfirm('Delete this probe and all of its reports? Its token stops working immediately.')) return;
  try {
    await opsFetch('/ops/probes/' + Number(id), { method: 'DELETE' });
    loadSentinelView();
  } catch (e) {
    toast(e.message, 'error');
  }
}

/* ── Carrier steering & diagnostics ── */
async function loadRoutingView() {
  try {
    const d = await opsFetch('/ops/carriers?hours=24');
    const body = document.getElementById('routing-matrix-body');
    if (!d.carriers.length) {
      tableMessage('routing-matrix-body', 5, 'No probe reports in the last 24 h. Add a probe under Sentinel Probes.');
    } else {
      body.innerHTML = d.carriers.map(c => '<tr>' +
        '<td><strong>' + esc(c.carrier) + '</strong></td>' +
        '<td>' + (c.best ? '<strong class="tactical-accent">' + esc(c.best.name) + '</strong>' : pill('danger', 'NOTHING GETS THROUGH')) + '</td>' +
        '<td>' + (c.best ? pill(okClass(c.best.ok_rate), fmtPct(c.best.ok_rate)) + '<div class="ops-cell-sub">' + fmtTests(c.best.attempts) + '</div>' : '—') + '</td>' +
        '<td class="tactical-mono">' + (c.best ? fmtMs(c.best.median_ms) : '—') + '</td>' +
        '<td class="tactical-muted">' + esc(fmtAgo(c.last_report_at)) + '</td>' +
      '</tr>').join('');
    }
    const fo = document.getElementById('routing-failover');
    if (fo) {
      const r = d.rotation, blocked = new Set(r.blocked);
      fo.innerHTML = r.order.map(p => {
        const cls = blocked.has(p) ? 'danger' : (p === r.active ? 'online' : 'muted');
        const label = p + (blocked.has(p) ? ' · BLOCKED' : (p === r.active ? ' · PREFERRED' : '')) +
          (r.failures[p] ? ' · ' + r.failures[p] + ' fail' : '');
        return pill(cls, label);
      }).join('');
    }
  } catch (e) {
    tableMessage('routing-matrix-body', 5, 'Could not load: ' + e.message);
  }
}

async function loadCarriersView() {
  const container = document.getElementById('carrier-test-results');
  if (!container) return;
  const hours = (document.getElementById('diag-hours') || {}).value || 24;
  try {
    const d = await opsFetch('/ops/carriers?hours=' + encodeURIComponent(hours));
    if (!d.carriers.length) {
      container.innerHTML = '<div class="tactical-card tactical-empty">No probe reports in this window. Create a probe under Sentinel Probes and run it inside Iran.</div>';
      return;
    }
    container.innerHTML = '<div class="tactical-grid">' + d.carriers.map(c =>
      '<div class="tactical-card tactical-stack">' +
        '<div class="tactical-card-head"><strong>' + esc(c.carrier) + '</strong>' +
          '<span class="tactical-muted tactical-mono">' + esc(fmtAgo(c.last_report_at)) + '</span></div>' +
        c.protocols.map(p =>
          '<div class="ops-proto-row">' +
            '<span class="ops-proto-name">' + esc(p.name) + '</span>' +
            '<progress class="ops-progress ops-progress-' + okClass(p.ok_rate) + '" max="1" value="' + Number(p.ok_rate) + '"></progress>' +
            '<span class="tactical-mono">' + fmtPct(p.ok_rate) + '</span>' +
            '<span class="tactical-mono tactical-muted">' + fmtMs(p.median_ms) + '</span>' +
          '</div>'
        ).join('') +
      '</div>'
    ).join('') + '</div>';
  } catch (e) {
    container.innerHTML = '<div class="tactical-card tactical-empty">Could not load: ' + esc(e.message) + '</div>';
  }
}

/* ── Financials ── */
function fmtMoney(amount, currency) {
  if (currency === 'USDT') return Number(amount || 0).toFixed(2) + ' USDT';
  return Math.round(amount || 0).toLocaleString('en-US');
}

async function loadFinancialsView() {
  try {
    const d = await opsFetch('/ops/financials');
    const t = (bucket, cur) => d[bucket][cur] || { count: 0, amount: 0 };
    setText('fin-irr-30d', fmtMoney(t('paid_30d', 'IRR').amount, 'IRR'));
    setText('fin-irr-all', 'All time: ' + fmtMoney(t('paid_all', 'IRR').amount, 'IRR') + ' · ' + t('paid_all', 'IRR').count + ' payments');
    setText('fin-usdt-30d', fmtMoney(t('paid_30d', 'USDT').amount, 'USDT'));
    setText('fin-usdt-all', 'All time: ' + fmtMoney(t('paid_all', 'USDT').amount, 'USDT') + ' · ' + t('paid_all', 'USDT').count + ' payments');
    setText('fin-pending', d.pending);
    setText('fin-balances', fmtMoney(d.resellers.balance_total_irr, 'IRR'));
    setText('fin-resellers', d.resellers.count + ' resellers' + (d.resellers.top.length ? ' · top: ' + d.resellers.top[0].username : ''));

    const gw = document.getElementById('fin-gateways');
    if (gw) gw.innerHTML = d.gateways.map(g =>
      pill(g.configured ? 'online' : 'muted', g.name + (g.configured ? ' · configured' : ' · not configured'))
    ).join('');

    const statusCls = { paid: 'online', pending: 'warning', failed: 'danger', expired: 'danger', refunded: 'muted' };
    const tx = document.getElementById('financials-tx-body');
    if (!d.recent_payments.length) tableMessage('financials-tx-body', 6, 'No payments yet.');
    else tx.innerHTML = d.recent_payments.map(p => '<tr>' +
      '<td class="tactical-mono">#' + Number(p.id) + '</td>' +
      '<td>' + esc(p.gateway) + '</td>' +
      '<td class="tactical-mono tactical-accent"><strong>' + esc(fmtMoney(p.amount, p.currency)) + '</strong>' + (p.currency === 'IRR' ? ' <span class="tactical-muted">IRR</span>' : '') + '</td>' +
      '<td>' + pill(statusCls[p.status] || 'muted', p.status) + '</td>' +
      '<td>' + esc(p.reseller || '—') + '</td>' +
      '<td class="tactical-muted">' + esc(fmtAgo(p.created_at)) + '</td>' +
    '</tr>').join('');

    const lg = document.getElementById('financials-ledger-body');
    if (!d.ledger.length) tableMessage('financials-ledger-body', 5, 'No ledger entries yet.');
    else lg.innerHTML = d.ledger.map(e => '<tr>' +
      '<td><strong>' + esc(e.reseller) + '</strong></td>' +
      '<td>' + esc(e.kind) + '</td>' +
      '<td class="tactical-mono ' + (e.amount_irr < 0 ? 'ops-red' : 'ops-green') + '">' + (e.amount_irr > 0 ? '+' : '') + esc(fmtMoney(e.amount_irr, 'IRR')) + '</td>' +
      '<td class="tactical-muted">' + esc(e.note || '') + '</td>' +
      '<td class="tactical-muted">' + esc(fmtAgo(e.created_at)) + '</td>' +
    '</tr>').join('');
  } catch (e) {
    tableMessage('financials-tx-body', 6, 'Could not load: ' + e.message);
  }
}

async function verifySecurityAudit() {
  try {
    const r = await fetch(API + '/security/audit/verify');
    const d = await r.json();
    if (!r.ok) {
      uiNotice('Audit verification failed: ' + (d.detail || ('HTTP ' + r.status)), 'error');
    } else if (d.ok) {
      uiNotice('Audit hash-chain intact: ' + d.checked + ' entries verified.', 'ok');
    } else {
      uiNotice('AUDIT LOG TAMPERED: hash-chain broken at entry #' + d.broken_at + ' (' + d.checked + ' entries checked).', 'error');
    }
  } catch (e) {
    uiNotice('Audit verification failed: ' + e.message, 'error');
  }
}

async function loadSecurityView() {
  const container = document.getElementById('security-audit-body');
  if (!container) return;
  try {
    const r = await fetch(API + '/security/audit?limit=10');
    const d = await r.json();
    if (!r.ok || !Array.isArray(d)) {
      container.innerHTML = '<tr><td colspan="4" class="tactical-empty">Could not load audit log: ' + esc(d.detail || ('HTTP ' + r.status)) + '</td></tr>';
      return;
    }
    if (!d.length) {
      container.innerHTML = '<tr><td colspan="4" class="tactical-empty">No audit entries yet.</td></tr>';
      return;
    }
    container.innerHTML = d.map(entry => {
      const actor = entry.admin_id != null ? 'admin #' + entry.admin_id : (entry.ip_address || 'system');
      return '<tr>' +
        '<td class="tactical-mono">' + esc((entry.created_at || '').replace('T', ' ').slice(0, 19)) + '</td>' +
        '<td><strong>' + esc(entry.action) + '</strong></td>' +
        '<td class="tactical-mono">' + esc(actor) + '</td>' +
        '<td class="tactical-mono tactical-hash" title="' + esc(entry.entry_hash) + '">' + esc(entry.entry_hash ? entry.entry_hash.slice(0, 16) + '…' : 'unsigned') + '</td>' +
      '</tr>';
    }).join('');
  } catch (e) {
    container.innerHTML = '<tr><td colspan="4" class="tactical-empty">Could not load audit log: ' + esc(e.message) + '</td></tr>';
  }
}

function switchTheme(theme) {
  if (!['obsidian', 'cyberops', 'midnight'].includes(theme)) theme = 'obsidian';
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem('spiritus_theme', theme); } catch (e) {}
  const name = { obsidian: 'Obsidian', cyberops: 'CyberOps', midnight: 'Midnight' }[theme];
  document.querySelectorAll('#theme-label, [data-theme-label]').forEach(lbl => { lbl.textContent = name; });
}

function cycleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'obsidian';
  const next = current === 'obsidian' ? 'cyberops' : (current === 'cyberops' ? 'midnight' : 'obsidian');
  switchTheme(next);
}

// Theme only: the tenants view is active in the markup, and its data is
// loaded after authentication. Fetching here, before login, hit fetchUsers'
// 401 -> location.reload() path and reloaded the login page in a loop.
document.addEventListener('DOMContentLoaded', function() {
  let saved = 'obsidian';
  try { saved = localStorage.getItem('spiritus_theme') || 'obsidian'; } catch (e) {}
  switchTheme(saved);
  setupLoginForm();
});

function setupLoginForm() {
  const user = document.getElementById('login-user');
  const pass = document.getElementById('login-pass');
  if (user && pass) {
    user.addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); pass.focus(); }
    });
  }
  const transport = document.getElementById('login-transport');
  if (transport) {
    const secure = location.protocol === 'https:';
    transport.textContent = secure ? 'HTTPS' : 'HTTP · UNENCRYPTED';
    transport.className = 'status-pill ' + (secure ? 'online' : 'warning');
    transport.title = secure ? 'Connection is encrypted' : 'This connection is not encrypted. Put the panel behind TLS before using it over the internet.';
  }
  setText('ui-transport', location.protocol === 'https:' ? 'HTTPS session · HttpOnly cookie' : 'HTTP · unencrypted session');
}
