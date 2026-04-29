const API = '/api';
// QR_LIB_URL and SERVER_INFO are injected by the template in panel.html
let users = [];
let prevLive = {}, prevTime = 0, speeds = {};
let renewTarget = '';
let polling = false;
let currentFilter = 'all';
let serverInfo = {};
let configTab = 'vmess';
let configTarget = null;
let mainView = 'users';
let groups = [];
// SERVER_INFO is injected by the template in panel.html

/* ── Auth ── */
async function doLogin() {
  const pw = document.getElementById('login-pass').value;
  const errEl = document.getElementById('login-error');
  const btn = document.getElementById('login-submit');
  if (!btn) return;
  errEl.textContent = '';
  btn.disabled = true;
  btn.textContent = 'Signing in...';
  try {
    const r = await fetch(API + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw }),
      credentials: 'same-origin'
    });
    let d = {};
    try {
      d = await r.json();
    } catch (e) {
      errEl.textContent = 'Invalid server response';
      btn.disabled = false;
      btn.textContent = 'Sign In';
      return;
    }
    if (r.ok && d.ok) {
      document.getElementById('login-screen').style.display = 'none';
      document.getElementById('panel').style.display = 'block';
      startPolling();
      btn.disabled = false;
      btn.textContent = 'Sign In';
      return;
    }
    errEl.textContent = d.error || 'Error';
    if (d.locked) {
      btn.disabled = true;
      btn.textContent = 'Locked';
      setTimeout(() => {
        btn.disabled = false;
        btn.textContent = 'Sign In';
        errEl.textContent = '';
      }, 60000);
      return;
    }
    btn.disabled = false;
    btn.textContent = 'Sign In';
    document.getElementById('login-pass').value = '';
    document.getElementById('login-pass').focus();
  } catch (e) {
    errEl.textContent = 'Connection error';
    btn.disabled = false;
    btn.textContent = 'Sign In';
  }
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
  } catch(e) {}
}

async function fetchGroups() {
  try {
    const r = await fetch(API+'/groups');
    if (r.status === 401) { location.reload(); return; }
    groups = await r.json();
    if (mainView === 'groups') renderGroups();
  } catch(e) {}
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
  } catch(e) {}
}

async function fetchServerInfo() {
  try {
    const r = await fetch(API+'/server-info');
    if (r.ok) {
      serverInfo = await r.json();
      updateProtoBar();
      updateSettingsStatus();
    }
  } catch(e) {}
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
  fr.style.display = serverInfo.fragment_enabled ? '' : 'none';
  mx.style.display = serverInfo.mux_enabled ? '' : 'none';
  ks.textContent = 'Kill Switch: ' + (serverInfo.kill_switch ? 'ON' : 'OFF');
  ks.className = 'proto-badge proto-ks' + (serverInfo.kill_switch ? '' : ' off');
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
function renderUsers() {
  const grid = document.getElementById('users-grid');
  const filtered = getFilteredUsers();
  updateFilterCounts();
  if (!users.length) {
    grid.innerHTML = '<div class="empty"><div class="empty-icon">📡</div><div class="empty-text">No users created yet</div></div>';
    return;
  }
  if (!filtered.length) {
    grid.innerHTML = '<div class="empty"><div class="empty-icon">🔍</div><div class="empty-text">No users match this filter</div></div>';
    return;
  }
  grid.innerHTML = filtered.map(u => {
    const spd = speeds[u.name] || {up:0, down:0};
    const online = isOnline(u.name);
    const barColor = u.traffic_percent < 60 ? 'var(--green)' : u.traffic_percent < 85 ? 'var(--yellow)' : 'var(--red)';
    const daysClass = u.days_left <= 3 ? 'crit' : u.days_left <= 7 ? 'warn' : 'val';
    const noteHtml = u.note ? `<div class="note-badge" title="${esc(u.note)}" onclick="event.stopPropagation();promptEditNote('${esc(u.name)}','${esc(u.note)}')">${esc(u.note)}</div>` : '';
    const ipCount = u.online_ip_count || 0;
    const ipHtml = ipCount > 0 ? `<span class="ip-badge" onclick="event.stopPropagation();showUserIPs('${esc(u.name)}')" title="Connected IPs">🌐 ${ipCount} IP${ipCount>1?'s':''}</span>` : '';
    const speedHtml = `<span style="font-size:10px;color:var(--t3);margin-left:4px;cursor:pointer" title="Speed limit (click to edit): Down ${u.speed_limit_down} KB/s, Up ${u.speed_limit_up} KB/s" onclick="event.stopPropagation();promptSpeed('${esc(u.name)}',${u.speed_limit_down},${u.speed_limit_up})">⚡${u.speed_limit_down}KB/s</span>`;
    return `
    <div class="card ${u.active?'':'inactive'}" id="card-${u.name}">
      <div class="card-head">
        <div class="card-name">
          <span class="online-dot ${online?'on':''}" id="dot-${u.name}"></span>
          <span class="user-name">${esc(u.name)}</span>
          ${speedHtml}
          ${ipHtml}
        </div>
        <span class="badge ${u.active?'badge-active':'badge-inactive'}">${u.active?'Active':'Disabled'}</span>
      </div>
      ${noteHtml}
      <div class="traffic-section">
        <div class="progress-track"><div class="progress-fill" style="width:${u.traffic_percent}%;background:${barColor}"></div></div>
        <div class="traffic-text"><span><b>${fmtTraffic(u.traffic_used_bytes)}</b> / ${fmtTraffic(u.traffic_limit_bytes)}</span><span>${u.traffic_percent}%</span></div>
      </div>
      <div class="info-row"><span>Expires</span><span class="val">${u.expire_at}</span></div>
      <div class="info-row"><span>Remaining</span><span class="${daysClass}">${u.days_left} days</span></div>
      <div class="speed-row" id="speed-${u.name}">
        <div class="speed-item up"><span>Upload</span><span class="speed-val">${fmtSpeed(spd.up)}</span></div>
        <div class="speed-item down"><span>Download</span><span class="speed-val">${fmtSpeed(spd.down)}</span></div>
      </div>
      <div class="card-actions">
        <button class="btn btn-outline btn-sm" onclick="showConfig('${esc(u.name)}')">Config</button>
        <button class="btn btn-outline btn-sm" onclick="showActivity('${esc(u.name)}')">Activity</button>
        <button class="btn ${u.active?'btn-orange':'btn-green'} btn-sm" onclick="toggleUser('${esc(u.name)}')">${u.active?'Disconnect':'Connect'}</button>
        <button class="btn btn-outline btn-sm" onclick="showRenew('${esc(u.name)}')">Renew</button>
        <button class="btn btn-green btn-sm" onclick="showAddTraffic('${esc(u.name)}')" title="Add traffic without reset">+GB</button>
        <button class="btn btn-danger btn-sm" onclick="deleteUser('${esc(u.name)}')">Delete</button>
      </div>
    </div>`;
  }).join('');
}

function renderGroups() {
  const grid = document.getElementById('groups-grid');
  if (!groups || !groups.length) {
    grid.innerHTML = '<div class="empty"><div class="empty-icon">🧩</div><div class="empty-text">No groups yet</div></div>';
    return;
  }
  grid.innerHTML = groups.map(g => {
    const pctActive = g.count ? Math.round((g.active / g.count) * 100) : 0;
    return `
    <div class="card">
      <div class="card-head">
        <div class="card-name">
          <span class="online-dot ${g.active>0?'on':''}"></span>
          <span class="user-name">${esc(g.id)}</span>
        </div>
        <span class="badge ${g.active>0?'badge-active':'badge-inactive'}">${g.active>0?'Active':'Disabled'}</span>
      </div>
      <div class="info-row"><span>Total</span><span class="val">${g.count}</span></div>
      <div class="info-row"><span>Active</span><span class="val">${g.active} (${pctActive}%)</span></div>
      <div class="info-row"><span>Disabled</span><span class="val">${g.disabled}</span></div>
      <div class="info-row"><span>Traffic</span><span class="val">${(g.traffic_gb||0)} GB each</span></div>
      <div class="info-row"><span>Latest expiry</span><span class="val">${(g.latest_expire||'').slice(0,10)}</span></div>
      <div class="card-actions">
        <button class="btn btn-outline btn-sm" onclick="openGroupExport('${esc(g.id)}')">Export</button>
        <button class="btn btn-outline btn-sm" onclick="openGroupUsers('${esc(g.id)}')">Open</button>
        <button class="btn btn-danger btn-sm" onclick="deleteGroup('${esc(g.id)}')">Delete</button>
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
  if (!confirm(`Delete group "${groupId}" from database?\n\nThis will not reload server (no disruption). Use Sync later to apply.`)) return;
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
    if (el) el.innerHTML = `
      <div class="speed-item up"><span>Upload</span><span class="speed-val">${fmtSpeed(spd.up)}</span></div>
      <div class="speed-item down"><span>Download</span><span class="speed-val">${fmtSpeed(spd.down)}</span></div>`;
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
  updateFilterCounts();
}

/* ── Actions ── */
async function doAddUser() {
  const name = document.getElementById('add-name').value.trim();
  const traffic = parseFloat(document.getElementById('add-traffic').value);
  const days = parseInt(document.getElementById('add-days').value);
  const note = (document.getElementById('add-note').value || '').trim();
  const speed_limit_down = parseInt(document.getElementById('add-speed-down').value) || 200;
  const speed_limit_up = parseInt(document.getElementById('add-speed-up').value) || 200;
  if (!name) {toast('Please enter a username','error'); return;}
  const r = await fetch(API+'/users', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({name, traffic, days, speed_limit_up, speed_limit_down, note})});
  const d = await r.json();
  if (d.ok) {
    closeModal('add-modal');
    document.getElementById('add-name').value = '';
    document.getElementById('add-note').value = '';
    document.getElementById('add-speed-down').value = '200';
    document.getElementById('add-speed-up').value = '200';
    toast('User '+name+' created');
    fetchUsers();
    setTimeout(()=>showConfig(name), 1500);
  } else { toast(d.error||'Error','error'); }
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
  const speed_limit_down = parseInt(document.getElementById('bulk-speed-down').value) || 200;
  const speed_limit_up = parseInt(document.getElementById('bulk-speed-up').value) || 200;
  const apply = document.getElementById('bulk-apply').checked;
  if (apply && !confirm('Apply to server now? This may reload config.')) return;

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
    return `<button class="bulk-tab ${active?'active':''}" onclick="selectBulkRun('${r.id}')">${esc(r.label||'group')}</button>`;
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
  <style>
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
    <script type=\"application/json\" id=\"bulk-json\">${usersJson}<\/script>
    <script src=\"${QR_LIB_URL}\"><\/script>
    <script>
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
  if (!confirm(msg)) return;

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
  if (!confirm(`${action === 'disconnect' ? 'Disconnect' : 'Reconnect'} "${name}"?`)) return;
  const r = await fetch(API+'/users/'+encodeURIComponent(name)+'/toggle', {method:'POST'});
  const d = await r.json();
  if (d.ok) { toast(d.message); fetchUsers(); }
  else toast(d.error||'Error','error');
}

async function deleteUser(name) {
  if (!confirm('Are you sure you want to delete "'+name+'"?')) return;
  const r = await fetch(API+'/users/'+encodeURIComponent(name), {method:'DELETE'});
  const d = await r.json();
  if (d.ok) {toast(name+' deleted'); fetchUsers();}
  else toast(d.error||'Error','error');
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
  const r = await fetch(API+'/users/'+encodeURIComponent(renewTarget)+'/renew',
    {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({traffic, days})});
  const d = await r.json();
  if (d.ok) {closeModal('renew-modal'); toast(renewTarget+' renewed'); fetchUsers();}
  else toast(d.error||'Error','error');
}

/* ── Config Modal (multi-protocol tabs) ── */
function showConfig(name) {
  const u = users.find(x=>x.name===name);
  if (!u) return;
  configTarget = u;
  document.getElementById('config-name').textContent = name;

  const vlTab = document.getElementById('ct-vless');
  const cdTab = document.getElementById('ct-cdn');
  const trTab = document.getElementById('ct-trojan');
  const grTab = document.getElementById('ct-grpc');
  const huTab = document.getElementById('ct-httpupgrade');
  const ssTab = document.getElementById('ct-ss2022');
  const vwTab = document.getElementById('ct-vless_ws');
  vlTab.style.display = serverInfo.vless ? '' : 'none';
  cdTab.style.display = serverInfo.cdn ? '' : 'none';
  trTab.style.display = serverInfo.trojan ? '' : 'none';
  grTab.style.display = serverInfo.grpc ? '' : 'none';
  huTab.style.display = serverInfo.httpupgrade ? '' : 'none';
  ssTab.style.display = serverInfo.ss2022 ? '' : 'none';
  vwTab.style.display = serverInfo.vless_ws ? '' : 'none';

  configTab = 'vmess';
  document.querySelectorAll('.config-tab').forEach(t => t.classList.remove('active'));
  document.querySelector('.tab-vmess').classList.add('active');
  renderConfigTab();
  // Sub link
  const subUrl = location.origin + '/sub/' + u.uuid;
  document.getElementById('config-sub-url').value = subUrl;
  document.getElementById('config-sub-open').href = subUrl;
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
      <span class="ck">Port</span><span class="cv">${SERVER_INFO.port}</span>
      <span class="ck">UUID</span><span class="cv" style="font-size:10px;word-break:break-all">${u.uuid}</span>
      <span class="ck">Network</span><span class="cv">WebSocket</span>
      <span class="ck">Path</span><span class="cv">${SERVER_INFO.path}</span>
      <span class="ck">TLS</span><span class="cv">Enabled</span>
      <span class="ck">SNI</span><span class="cv">${SERVER_INFO.sni}</span>`;
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

function copySubUrl() {
  const v = document.getElementById('config-sub-url').value;
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
  set('si-vless', si.vless, si.vless ? 'Active :' + (si.vless_port || 2053) : 'OFF — Keys needed');
  set('si-trojan', si.trojan, si.trojan ? 'Active :' + (si.trojan_port || 2083) : 'OFF');
  set('si-grpc', si.grpc, si.grpc ? 'Active :' + (si.grpc_port || 2054) : 'OFF');
  set('si-hu', si.httpupgrade, si.httpupgrade ? 'Active :' + (si.httpupgrade_port || 2055) : 'OFF');
  set('si-ss2022', si.ss2022, si.ss2022 ? 'Active :' + (si.ss2022_port || 2056) : 'OFF');
  set('si-vless-ws', si.vless_ws, si.vless_ws ? 'Active :' + (si.vless_ws_port || 2057) : 'OFF');
  set('si-cdn', si.cdn, si.cdn ? 'Active — ' + (si.cdn_domain || '?') : 'OFF');
  set('si-ks', si.kill_switch, si.kill_switch ? 'ON' : 'OFF');
  set('si-fragment', si.fragment_enabled, si.fragment_enabled ? 'ON (client)' : 'OFF');
  set('si-mux', si.mux_enabled, si.mux_enabled ? 'ON (client)' : 'OFF');
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
  try {
    const r = await fetch(API+'/settings');
    if (!r.ok) return;
    const s = await r.json();
    // Config customization
    document.getElementById('set-config-prefix').value = s.config_prefix || 'Proxy';
    document.getElementById('set-vmess-port').value = s.vmess_port || 443;
    document.getElementById('set-vmess-sni').value = s.vmess_sni || 'www.aparat.com';
    document.getElementById('set-vmess-ws-path').value = s.vmess_ws_path || '/api/v1/stream';
    // Security
    document.getElementById('set-ks').checked = s.kill_switch_enabled;
    // VLESS / Reality
    document.getElementById('set-reality-sni').value = s.reality_sni || 'www.google.com';
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
    document.getElementById('set-dpi-dns-tunnel').checked = s.dpi_dns_tunnel || false;
    document.getElementById('set-dpi-icmp-tunnel').checked = s.dpi_icmp_tunnel || false;
    document.getElementById('set-dpi-domain-front').checked = s.dpi_domain_front || false;
    document.getElementById('set-dpi-cdn-front-enabled').checked = s.dpi_cdn_front_enabled || false;
    document.getElementById('set-dpi-cdn-front').value = s.dpi_cdn_front || '';
    loadBackups();
    updateSettingsStatus();
  } catch(e) {}
}

async function saveSettings() {
  const data = {
    // Config customization
    config_prefix: document.getElementById('set-config-prefix').value.trim() || 'Proxy',
    vmess_port: parseInt(document.getElementById('set-vmess-port').value) || 443,
    vmess_sni: document.getElementById('set-vmess-sni').value.trim() || 'www.aparat.com',
    vmess_ws_path: document.getElementById('set-vmess-ws-path').value.trim() || '/api/v1/stream',
    // Security
    kill_switch_enabled: document.getElementById('set-ks').checked,
    // VLESS / Reality
    reality_sni: document.getElementById('set-reality-sni').value.trim() || 'www.google.com',
    reality_dest: (document.getElementById('set-reality-sni').value.trim() || 'www.google.com') + ':443',
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
    dpi_dns_tunnel: document.getElementById('set-dpi-dns-tunnel').checked,
    dpi_icmp_tunnel: document.getElementById('set-dpi-icmp-tunnel').checked,
    dpi_domain_front: document.getElementById('set-dpi-domain-front').checked,
    dpi_cdn_front_enabled: document.getElementById('set-dpi-cdn-front-enabled').checked,
    dpi_cdn_front: document.getElementById('set-dpi-cdn-front').value.trim(),
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

function toggleKillSwitch() {}
function toggleCDN() {}

async function regenerateReality() {
  if (!confirm('Generate new Reality keys? Existing VLESS configs will stop working.')) return;
  const r = await fetch(API+'/settings/regenerate-reality', {method:'POST'});
  const d = await r.json();
  if (d.ok) {
    toast('Reality keys regenerated — server restarted');
    document.getElementById('vless-status').textContent = 'Active — Key: ' + d.public_key.substring(0, 16) + '...';
    fetchServerInfo();
  } else toast(d.error||'Error','error');
}

async function generateSS2022Key() {
  if (!confirm('Generate new SS2022 server key? Existing SS2022 configs will need updating.')) return;
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
  document.querySelectorAll('.config-tabs .config-tab').forEach(el => el.classList.remove('active'));
  // Show selected tab content
  const content = document.getElementById('settings-' + tabName);
  if (content) content.classList.add('active');
  // Activate corresponding button
  const btn = document.querySelector('.config-tabs .config-tab[onclick*="'+tabName+'"]');
  if (btn) btn.classList.add('active');
}

function switchAggressiveTab(tab) {
  document.querySelectorAll('.aggressive-tab-content').forEach(el => el.style.display = 'none');
  document.querySelectorAll('#aggressive-modal .config-tab').forEach(el => el.classList.remove('active'));
  const content = document.getElementById('aggressive-tab-' + tab);
  if (content) content.style.display = 'block';
  const btn = document.querySelector('#aggressive-modal .config-tab[onclick*="'+tab+'"]');
  if (btn) btn.classList.add('active');
}

function switchFightbackTab(tab) {
  document.querySelectorAll('.fightback-tab-content').forEach(el => el.style.display = 'none');
  document.querySelectorAll('#fightback-modal .config-tab').forEach(el => el.classList.remove('active'));
  const content = document.getElementById('fightback-tab-' + tab);
  if (content) content.style.display = 'block';
  const btn = document.querySelector('#fightback-modal .config-tab[onclick*="'+tab+'"]');
  if (btn) btn.classList.add('active');
}

/* ── Helpers ── */
function showModal(id) {
  document.getElementById(id).classList.add('show');
  if (id === 'settings-modal') { loadSettings(); switchSettingsTab('protocols'); }
  if (id === 'agents-modal') fetchAgents();
  if (id === 'sysmon-modal') openSysmonDetail();
  if (id === 'online-modal') fetchOnlineUsers();
}
function closeModal(id){document.getElementById(id).classList.remove('show')}
function hideModal(id){document.getElementById(id).classList.remove('show')}
function esc(s){if(!s)return '';return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}

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
  } catch(e) {}
}

function renderAgents() {
  const el = document.getElementById('agents-list');
  if (!el) return;
  if (!_agents.length) {
    el.innerHTML = '<div style="color:var(--t3);font-size:13px;text-align:center;padding:20px">No agents yet</div>';
    return;
  }
  el.innerHTML = _agents.map(a => {
    const pct = a.traffic_quota_gb > 0 ? Math.min(100, Math.round((a.traffic_used_gb / a.traffic_quota_gb) * 100)) : 0;
    const barColor = pct < 60 ? 'var(--green)' : pct < 85 ? 'var(--yellow)' : 'var(--red)';
    const remaining = Math.max(0, a.traffic_quota_gb - a.traffic_used_gb);
    return `<div class="agent-card">
      <div class="agent-card-head">
        <span class="agent-card-name">${esc(a.name)}</span>
        <span class="badge ${a.active?'badge-active':'badge-inactive'}">${a.active?'Active':'Disabled'}</span>
      </div>
      <div class="agent-info">
        <span>Quota: <b style="color:var(--t0)">${a.traffic_used_gb} / ${a.traffic_quota_gb} GB</b></span>
        <span>Remaining: <b style="color:var(--t0)">${remaining.toFixed(1)} GB</b></span>
        <span>Users: <b style="color:var(--t0)">${a.user_count}</b></span>
      </div>
      <div class="agent-quota-bar"><div class="agent-quota-fill" style="width:${pct}%;background:${barColor}"></div></div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-top:4px">
        <span style="font-size:11px;color:var(--t3)">${pct}% used</span>
        <span style="font-size:11px;color:var(--t3)">Login: /agent</span>
      </div>
      <div class="agent-actions" style="margin-top:10px">
        <button class="btn btn-outline btn-sm" onclick="showEditAgent(${a.id},'${esc(a.name)}',${a.traffic_quota_gb})">Edit Quota</button>
        <button class="btn btn-outline btn-sm" onclick="showResetAgentPw(${a.id},'${esc(a.name)}')">Reset Pass</button>
        <button class="btn ${a.active?'btn-orange':'btn-green'} btn-sm" onclick="toggleAgent(${a.id},${a.active?0:1})">${a.active?'Disable':'Enable'}</button>
        <button class="btn btn-danger btn-sm" onclick="deleteAgent(${a.id},'${esc(a.name)}')">Delete</button>
      </div>
    </div>`;
  }).join('');
}

async function doAddAgent() {
  const name = document.getElementById('agent-add-name').value.trim();
  const pass = document.getElementById('agent-add-pass').value;
  const quota = parseFloat(document.getElementById('agent-add-quota').value);
  const speed = parseInt(document.getElementById('agent-add-speed').value) || 200;
  if (!name) { toast('Enter agent name','error'); return; }
  if (!pass || pass.length < 6) { toast('Password must be at least 6 chars','error'); return; }
  if (!quota || quota <= 0) { toast('Enter valid quota','error'); return; }
  const r = await fetch(API+'/agents', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({name, password: pass, traffic_quota_gb: quota, speed_limit_default: speed})});
  const d = await r.json();
  if (d.ok) {
    toast('Agent '+name+' created');
    document.getElementById('agent-add-name').value = '';
    document.getElementById('agent-add-pass').value = '';
    fetchAgents();
  } else { toast(d.error||'Error','error'); }
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
  const r = await fetch(API+'/agents/'+_agentEditId+'/edit', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({traffic_quota_gb: quota})});
  const d = await r.json();
  if (d.ok) { toast('Quota updated'); closeModal('agent-edit-modal'); fetchAgents(); }
  else { toast(d.error||'Error','error'); }
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
  if (!pw || pw.length < 6) { toast('Password must be at least 6 chars','error'); return; }
  const r = await fetch(API+'/agents/'+_agentPwId+'/reset-password', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({password: pw})});
  const d = await r.json();
  if (d.ok) { toast('Password reset'); closeModal('agent-pw-modal'); }
  else { toast(d.error||'Error','error'); }
}

async function toggleAgent(id, newState) {
  const r = await fetch(API+'/agents/'+id+'/edit', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({active: !!newState})});
  const d = await r.json();
  if (d.ok) { toast(newState?'Agent enabled':'Agent disabled'); fetchAgents(); }
  else { toast(d.error||'Error','error'); }
}

async function deleteAgent(id, name) {
  if (!confirm('Delete agent "'+name+'"?\\n\\nTheir users will be transferred to admin.')) return;
  const r = await fetch(API+'/agents/'+id, {method:'DELETE', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({delete_users: false})});
  const d = await r.json();
  if (d.ok) { toast('Agent deleted'); fetchAgents(); }
  else { toast(d.error||'Error','error'); }
}

/* ── System Monitor ── */
let sysmonData = {};

async function fetchSystemMonitor() {
  try {
    const r = await fetch(API+'/system-monitor');
    if (!r.ok) return;
    sysmonData = await r.json();
    renderSysmonBar();
  } catch(e) {}
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
  } catch(e) {}
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
  } catch(e) {}
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
    el.innerHTML = `<table class="online-tbl"><thead><tr><th>User</th><th>IPs</th><th>Count</th></tr></thead><tbody>` +
      data.map(u => `<tr>
        <td style="font-weight:600">${esc(u.username)}</td>
        <td style="font-family:monospace;font-size:11px">${(u.ips||[]).map(ip=>esc(ip)).join('<br>')}</td>
        <td>${(u.ips||[]).length}</td>
      </tr>`).join('') +
      `</tbody></table>`;
  } catch(e) { toast('Error fetching online users','error'); }
}

function showUserIPs(name) {
  const u = users.find(x=>x.name===name);
  if (!u || !u.online_ips || !u.online_ips.length) { toast('No IPs found','error'); return; }
  alert('Connected IPs for '+name+':\n\n'+u.online_ips.join('\n'));
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
  const note = prompt('Edit note for '+name+':', current || '');
  if (note === null) return;
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
  const val = prompt('Speed limit (KB/s) for ' + name + ':\nFormat: down,up (e.g. 200,200)\n0 = unlimited', currentDown + ',' + currentUp);
  if (val === null) return;
  const parts = val.split(',').map(s => parseInt(s.trim()));
  const down = parts[0] >= 0 ? parts[0] : 200;
  const up = parts.length > 1 && parts[1] >= 0 ? parts[1] : down;
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
async function runFirewallAttack(technique) {
  const targetIp = document.getElementById('firewall-target-ip').value.trim();
  const duration = parseInt(document.getElementById('firewall-duration').value) || 30;
  
  if (!targetIp) {
    toast('Please enter a target IP address', 'error');
    return;
  }
  
  try {
    const r = await fetch(API+'/network-resilience/run', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        technique: technique,
        target: targetIp,
        duration: duration
      })
    });
    const d = await r.json();
    if (d.ok) {
      toast(`Firewall resilience test '${technique}' initiated (simulation mode)`);
      fetchFirewallStats();
    } else {
      toast(d.error || 'Error running test', 'error');
    }
  } catch(e) {
    toast('Connection error', 'error');
  }
}

async function fetchFirewallStats() {
  try {
    const r = await fetch(API+'/network-resilience/stats');
    const d = await r.json();
    if (d.ok) {
      const statsEl = document.getElementById('firewall-stats-content');
      const displayEl = document.getElementById('firewall-stats-display');
      
      if (d.stats && Object.keys(d.stats).length > 0) {
        let html = '<div style="margin-bottom:8px">';
        for (const [attack, data] of Object.entries(d.stats)) {
          html += `<div style="margin-bottom:4px">
            <span style="color:var(--accent);font-weight:600">${attack}:</span>
            <span style="color:var(--t1);margin-left:8px">${JSON.stringify(data)}</span>
          </div>`;
        }
        html += '</div>';
        html += `<div style="color:var(--t3);font-size:11px">Active tests: ${d.active_attacks || 0}</div>`;
        statsEl.innerHTML = html;
        displayEl.style.display = 'block';
      } else {
        statsEl.innerHTML = '<div style="color:var(--t3);font-size:12px">No test statistics available</div>';
        displayEl.style.display = 'block';
      }
    }
  } catch(e) {
    toast('Error fetching firewall stats', 'error');
  }
}

async function stopFirewallAttacks() {
  if (!confirm('Stop all running resilience tests?')) return;
  
  try {
    const r = await fetch(API+'/network-resilience/stop', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'}
    });
    const d = await r.json();
    if (d.ok) {
      toast('All resilience tests stopped');
      fetchFirewallStats();
    } else {
      toast(d.error || 'Error stopping tests', 'error');
    }
  } catch(e) {
    toast('Connection error', 'error');
  }
}

function setTarget(ip) {
  document.getElementById('firewall-target-ip').value = ip;
  toast(`Target set to ${ip}`);
}

async function verifyNetworkTarget() {
  const targetIp = document.getElementById('firewall-target-ip').value.trim();
  
  if (!targetIp) {
    toast('Please enter a target IP address', 'error');
    return;
  }
  
  try {
    const r = await fetch(API+'/network-resilience/run', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        technique: 'syn_flood_enhanced',
        target: targetIp,
        duration: 1
      })
    });
    const d = await r.json();
    const resultEl = document.getElementById('verification-result-content');
    const displayEl = document.getElementById('target-verification-result');
    
    if (d.iranian_target) {
      resultEl.innerHTML = `<div style="color:var(--green);font-weight:600">✓ ${targetIp} is known network infrastructure</div>
        <div style="color:var(--t2);font-size:11px;margin-top:4px">This IP belongs to known known network ranges</div>`;
    } else {
      resultEl.innerHTML = `<div style="color:var(--red);font-weight:600">✗ ${targetIp} is NOT known network infrastructure</div>
        <div style="color:var(--t2);font-size:11px;margin-top:4px">This IP is not in known known network ranges</div>`;
    }
    
    displayEl.style.display = 'block';
  } catch(e) {
    toast('Error verifying target', 'error');
  }
}

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
  if (!confirm('Are you sure you want to restore this backup? This will replace current data.')) {
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
  if (!confirm('Are you sure you want to delete this backup?')) {
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

/* ── Resilience Operations ── */
let aggressiveAttacks = [];

function showAggressiveFields() {
  const attackType = document.getElementById('resilience-op-type').value;
  
  // Hide all optional fields
  document.getElementById('aggressive-ports-group').style.display = 'none';
  document.getElementById('aggressive-dns-group').style.display = 'none';
  document.getElementById('aggressive-ntp-group').style.display = 'none';
  document.getElementById('aggressive-url-group').style.display = 'none';
  
  // Show relevant fields
  if (attackType === 'udp_flood') {
    document.getElementById('aggressive-ports-group').style.display = 'block';
  } else if (attackType === 'dns_amp') {
    document.getElementById('aggressive-dns-group').style.display = 'block';
  } else if (attackType === 'ntp_amp') {
    document.getElementById('aggressive-ntp-group').style.display = 'block';
  } else if (attackType === 'http_flood') {
    document.getElementById('aggressive-url-group').style.display = 'block';
  }
}

async function startResilienceOp() {
  const targetIp = document.getElementById('aggressive-target-ip').value;
  const targetPort = parseInt(document.getElementById('aggressive-target-port').value);
  const duration = parseInt(document.getElementById('aggressive-duration').value);
  const attackType = document.getElementById('resilience-op-type').value;
  
  if (!targetIp || !targetPort || !duration) {
    toast('Please fill in all required fields', 'error');
    return;
  }
  
  const attackData = {
    target_ip: targetIp,
    target_port: targetPort,
    duration: duration,
    attack_type: attackType
  };
  
  // Add optional parameters
  if (attackType === 'udp_flood') {
    const ports = document.getElementById('aggressive-ports').value;
    attackData.ports = ports.split(',').map(p => parseInt(p.trim()));
  } else if (attackType === 'dns_amp') {
    const dnsServers = document.getElementById('aggressive-dns-servers').value;
    attackData.dns_servers = dnsServers.split(',').map(s => s.trim());
  } else if (attackType === 'ntp_amp') {
    const ntpServers = document.getElementById('aggressive-ntp-servers').value;
    attackData.ntp_servers = ntpServers.split(',').map(s => s.trim());
  } else if (attackType === 'http_flood') {
    attackData.target_url = document.getElementById('aggressive-target-url').value;
  }
  
  try {
    const r = await fetch(`${API}/aggressive/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(attackData),
      credentials: 'same-origin'
    });
    
    if (r.ok) {
      const data = await r.json();
      toast(`Aggressive attack started: ${attackType}`, 'success');
      document.getElementById('aggressive-status').style.display = 'block';
      document.getElementById('aggressive-status-text').textContent = `Attack running: ${attackType} on ${targetIp}:${targetPort}`;
      aggressiveAttacks.push(data.attack_id);
    } else {
      const error = await r.json();
      toast(`Failed to start attack: ${error.error}`, 'error');
    }
  } catch(e) {
    toast('Attack start error', 'error');
  }
}

async function stopResilienceOps() {
  try {
    const r = await fetch(`${API}/aggressive/stop`, {
      method: 'POST',
      credentials: 'same-origin'
    });
    
    if (r.ok) {
      toast('All resilience operations stopped', 'success');
      document.getElementById('aggressive-status').style.display = 'none';
      document.getElementById('aggressive-status-text').textContent = 'No active attacks';
      aggressiveAttacks = [];
    } else {
      toast('Failed to stop attacks', 'error');
    }
  } catch(e) {
    toast('Stop attack error', 'error');
  }
}

/* ── Counter Techniques ── */
let fightBackTechniques = [];

function showFightBackFields() {
  const technique = document.getElementById('fightback-technique').value;
  
  // Hide all optional fields
  document.getElementById('fightback-gateway-group').style.display = 'none';
  document.getElementById('fightback-dns-group').style.display = 'none';
  document.getElementById('fightback-domain-group').style.display = 'none';
  document.getElementById('fightback-fake-ip-group').style.display = 'none';
  document.getElementById('fightback-session-group').style.display = 'none';
  
  // Show relevant fields
  if (technique === 'icmp_redirect' || technique === 'arp_spoofing') {
    document.getElementById('fightback-gateway-group').style.display = 'block';
  } else if (technique === 'dns_poisoning') {
    document.getElementById('fightback-dns-group').style.display = 'block';
    document.getElementById('fightback-domain-group').style.display = 'block';
    document.getElementById('fightback-fake-ip-group').style.display = 'block';
  } else if (technique === 'session_hijacking') {
    document.getElementById('fightback-session-group').style.display = 'block';
  }
}

async function startFightBack() {
  const targetIp = document.getElementById('fightback-target-ip').value;
  const targetPort = parseInt(document.getElementById('fightback-target-port').value);
  const duration = parseInt(document.getElementById('fightback-duration').value);
  const technique = document.getElementById('fightback-technique').value;
  
  if (!targetIp || !targetPort || !duration) {
    toast('Please fill in all required fields', 'error');
    return;
  }
  
  const techniqueData = {
    target_ip: targetIp,
    target_port: targetPort,
    duration: duration,
    technique: technique
  };
  
  // Add optional parameters
  if (technique === 'icmp_redirect' || technique === 'arp_spoofing') {
    techniqueData.gateway_ip = document.getElementById('fightback-gateway-ip').value;
  } else if (technique === 'dns_poisoning') {
    techniqueData.dns_server = document.getElementById('fightback-dns-server').value;
    techniqueData.domain = document.getElementById('fightback-domain').value;
    techniqueData.fake_ip = document.getElementById('fightback-fake-ip').value;
  } else if (technique === 'session_hijacking') {
    techniqueData.session_id = document.getElementById('fightback-session-id').value;
  }
  
  try {
    const r = await fetch(`${API}/fightback/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(techniqueData),
      credentials: 'same-origin'
    });
    
    if (r.ok) {
      const data = await r.json();
      toast(`Fight back technique started: ${technique}`, 'success');
      document.getElementById('fightback-status').style.display = 'block';
      document.getElementById('fightback-status-text').textContent = `Technique running: ${technique} on ${targetIp}:${targetPort}`;
      fightBackTechniques.push(data.technique_id);
    } else {
      const error = await r.json();
      toast(`Failed to start technique: ${error.error}`, 'error');
    }
  } catch(e) {
    toast('Technique start error', 'error');
  }
}

async function stopFightBack() {
  try {
    const r = await fetch(`${API}/fightback/stop`, {
      method: 'POST',
      credentials: 'same-origin'
    });
    
    if (r.ok) {
      toast('All counter techniques stopped', 'success');
      document.getElementById('fightback-status').style.display = 'none';
      document.getElementById('fightback-status-text').textContent = 'No active techniques';
      fightBackTechniques = [];
    } else {
      toast('Failed to stop techniques', 'error');
    }
  } catch(e) {
    toast('Stop technique error', 'error');
  }
}

// Add event listeners for dropdown changes
document.addEventListener('DOMContentLoaded', function() {
  const aggressiveSelect = document.getElementById('resilience-op-type');
  if (aggressiveSelect) {
    aggressiveSelect.addEventListener('change', showAggressiveFields);
  }
  
  const fightbackSelect = document.getElementById('fightback-technique');
  if (fightbackSelect) {
    fightbackSelect.addEventListener('change', showFightBackFields);
  }
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
