/* PPPoE IP Manager frontend. Vanilla ES6+. All allocation data comes from the Flask API;
   localStorage only keeps non-sensitive UI preferences. Data is rendered with DOM methods
   (never innerHTML) so router-supplied text cannot inject markup. */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const REFRESH_MS = 30000;

  const VIEWS = {
    dashboard: { title: 'Dashboard', section: 'view-dashboard' },
    all: { title: 'IP inventory', section: 'view-ips', endpoint: '/api/inventory' },
    assigned: { title: 'Assigned IPs', section: 'view-ips', endpoint: '/api/assigned' },
    free: { title: 'Free IPs', section: 'view-ips', endpoint: '/api/free' },
    reports: { title: 'Reports', section: 'view-reports' },
    networks: { title: 'Networks', section: 'view-networks' },
  };
  const STATUS_LABEL = {
    assigned: 'Assigned', free: 'Free', reserved: 'Reserved', conflict: 'Conflict',
    active_unconfigured: 'Active unconfigured', unknown: 'Unknown',
  };

  // ------------------------------------------------------------------ preferences
  const prefs = {
    get(key, fallback = null) {
      try { const v = localStorage.getItem('ipmgr.' + key); return v === null ? fallback : v; }
      catch { return fallback; }
    },
    set(key, value) {
      try { localStorage.setItem('ipmgr.' + key, String(value)); } catch { /* storage unavailable */ }
    },
  };

  // ------------------------------------------------------------------ helpers
  function h(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
    return node;
  }
  const clear = (node) => { node.replaceChildren(); return node; };
  const fmtNum = (n) => Number(n).toLocaleString();
  const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString() : '');

  function toast(message, kind = 'ok') {
    const t = h('div', { class: 'toast ' + kind, role: kind === 'err' ? 'alert' : 'status', text: message });
    $('toasts').append(t);
    setTimeout(() => t.remove(), kind === 'err' ? 7000 : 3500);
  }

  class ApiError extends Error {
    constructor(message, status, data) { super(message); this.status = status; this.data = data; }
  }

  async function api(path, { method = 'GET', body } = {}) {
    const headers = { Accept: 'application/json', 'X-CSRF-Token': CSRF };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let res;
    try {
      res = await fetch(path, {
        method, headers, credentials: 'same-origin',
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new ApiError('Cannot reach the IP Manager server. Check your connection.', 0, null);
    }
    if (res.status === 401) { window.location.href = '/login'; throw new ApiError('Signed out.', 401, null); }
    let data = null;
    try { data = await res.json(); } catch { /* non-JSON body */ }
    if (!res.ok || (data && data.ok === false)) {
      throw new ApiError((data && data.error) || `Request failed (${res.status}).`, res.status, data);
    }
    return data;
  }

  function legacyCopy(text) { // plain-HTTP LAN deployments have no async clipboard API
    const ta = h('textarea', { 'aria-hidden': 'true', tabindex: '-1' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    return ok;
  }

  async function copyText(text) {
    let ok = false;
    if (navigator.clipboard && window.isSecureContext) {
      try { await navigator.clipboard.writeText(text); ok = true; } catch { ok = false; }
    }
    if (!ok) ok = legacyCopy(text);
    if (ok) toast(`Copied ${text}`);
    else toast('Could not copy. Select the text and press Ctrl+C.', 'err');
  }

  // ------------------------------------------------------------------ theme
  function effectiveDark() {
    const t = document.documentElement.dataset.theme;
    if (t) return t === 'dark';
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }
  function applyTheme(t) {
    if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
    else delete document.documentElement.dataset.theme;
  }
  applyTheme(prefs.get('theme'));

  // ------------------------------------------------------------------ state
  const state = {
    view: 'dashboard',
    page: 1, sort: 'ip', dir: 'asc',
    inflight: false,
    tableSeq: 0,
    verified: false,
    hasNetworks: false,
    // networks editor
    cands: [], selected: new Set(), manual: [], netsDirty: false,
    chart: null,
  };

  // ------------------------------------------------------------------ connection status
  function applyStatus(st) {
    if (!st) return;
    state.verified = !!st.verified;
    const dot = $('connDot'), text = $('connText'), banner = $('banner');
    dot.className = 'dot';
    banner.hidden = true;
    banner.className = 'banner';
    if (st.stale) {
      dot.classList.add('dot-warn');
      text.textContent = 'Stale data';
      banner.className = 'banner warn';
      banner.textContent = `Router unreachable. Showing cached data from ${fmtTime(st.last_success)}. ` +
        'Free IPs cannot be verified until the router responds.' + (st.error ? ` (${st.error})` : '');
      banner.hidden = false;
    } else if (st.has_data) {
      dot.classList.add('dot-ok');
      text.textContent = st.router ? `Connected · ${st.router}` : 'Connected';
    } else if (st.error) {
      dot.classList.add('dot-bad');
      text.textContent = 'Router unavailable';
      banner.className = 'banner bad';
      banner.textContent = st.error;
      banner.hidden = false;
    } else {
      dot.classList.add('dot-idle');
      text.textContent = 'Connecting…';
    }
    $('syncTime').textContent = st.last_success ? `Last sync ${new Date(st.last_success).toLocaleTimeString()}` : 'Never synced';
    $('syncTime').title = st.last_success ? `Last successful synchronization: ${fmtTime(st.last_success)}` : 'No successful synchronization yet';
  }

  function showFatal(e, silent) {
    if (e.data && e.data.status) applyStatus(e.data.status);
    else if (e.status === 0) {
      $('connDot').className = 'dot dot-bad';
      $('connText').textContent = 'Server unreachable';
    }
    if (!silent) toast(e.message, 'err');
  }

  // ------------------------------------------------------------------ dashboard
  const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  function renderChart(stats, verified) {
    const other = Math.max(0, stats.total_ips - stats.assigned - stats.free);
    const values = [stats.assigned, stats.free, other];
    const labels = ['Assigned', 'Free', verified ? 'Other (reserved, conflict, active)' : 'Unverified / other'];
    const colors = [cssVar('--c-assigned'), cssVar('--c-free'), cssVar('--c-other')];
    $('utilPct').textContent = `${stats.utilization_pct}%`;
    $('meterFill').style.width = `${Math.min(100, stats.utilization_pct)}%`;
    $('utilNote').textContent = `${fmtNum(stats.total_ips)} monitored`;

    const legend = clear($('legend'));
    ['assigned', 'free', 'other'].forEach((k, i) => {
      legend.append(h('li', {}, h('span', { class: 'sw ' + k }), labels[i], h('b', { text: fmtNum(values[i]) })));
    });

    if (typeof Chart === 'undefined') return;
    if (state.chart) {
      state.chart.data.labels = labels;
      state.chart.data.datasets[0].data = values;
      state.chart.data.datasets[0].backgroundColor = colors;
      state.chart.update();
      return;
    }
    state.chart = new Chart($('doughnut'), {
      type: 'doughnut',
      data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
      options: {
        cutout: '72%', responsive: true, maintainAspectRatio: false, animation: { duration: 300 },
        plugins: { legend: { display: false } },
      },
    });
  }

  function statCard({ label, value, sub, tone, view, status }) {
    return h('button', {
      class: 'stat ' + (tone ? 't-' + tone : ''), type: 'button',
      title: `Open ${VIEWS[view].title}`, onclick: () => go(view, { status }),
    },
    h('span', { class: 'stat-label', text: label }),
    h('span', { class: 'stat-value', text: typeof value === 'number' ? fmtNum(value) : value }),
    sub ? h('span', { class: 'stat-sub', text: sub }) : null);
  }

  function renderStats(d) {
    const s = d.stats, ok = d.verified;
    const cards = [
      { label: 'Total monitored IPs', value: s.total_ips, tone: 'info', view: 'all' },
      { label: 'Assigned IPs', value: s.assigned, tone: 'info', view: 'assigned' },
      { label: 'Free IPs', value: ok ? s.free : 'Unverified', tone: 'ok', view: 'free',
        sub: ok ? 'No known PPPoE use' : `${fmtNum(s.unknown)} unknown (stale data)` },
      { label: 'Active PPPoE users', value: s.active_users, tone: 'info', view: 'all' },
      { label: 'Offline assigned users', value: s.offline_assigned, tone: s.offline_assigned ? 'warn' : '', view: 'assigned', sub: 'Assigned, not online' },
      { label: 'Disabled secrets', value: s.disabled_secrets, view: 'reports' },
      { label: 'IP conflicts', value: s.conflicts, tone: s.conflicts ? 'bad' : '', view: 'all', status: 'conflict' },
      { label: 'Out-of-range assignments', value: s.out_of_range, tone: s.out_of_range ? 'warn' : '', view: 'reports' },
      { label: 'Active unconfigured', value: s.active_unconfigured, tone: s.active_unconfigured ? 'warn' : '', view: 'all', status: 'active_unconfigured', sub: 'Online without a secret' },
    ];
    clear($('stats')).append(...cards.map(statCard));
  }

  function renderNetBars(networks) {
    const box = clear($('netBars'));
    networks.forEach((n) => {
      const pct = (x) => (n.total ? (100 * x) / n.total : 0);
      const seg = (cls, x) => { const i = h('i', { class: cls }); i.style.width = `${pct(x)}%`; return i; };
      box.append(h('div', { class: 'net-row' },
        h('span', { class: 'net-name', text: n.network }),
        h('div', { class: 'bar', role: 'img', 'aria-label': `${n.assigned} assigned, ${n.free} free, ${n.other} other of ${n.total}` },
          seg('b-assigned', n.assigned), seg('b-other', n.other), seg('b-free', n.free)),
        h('span', { class: 'net-meta', text: `${fmtNum(n.assigned)} assigned · ${state.verified ? fmtNum(n.free) + ' free' : 'free unverified'} · ${fmtNum(n.total)} total` })));
    });
  }

  function syncNetFilter(networks) {
    const sel = $('netFilter');
    const wanted = sel.value || prefs.get('subnet', '');
    clear(sel).append(h('option', { value: '', text: 'All networks' }));
    networks.forEach((n) => sel.append(h('option', { value: n.network, text: n.network })));
    sel.value = networks.some((n) => n.network === wanted) ? wanted : '';
  }

  async function loadDashboard() {
    const d = await api('/api/dashboard');
    applyStatus(d.status);
    state.hasNetworks = !d.needs_setup;
    $('dashSetup').hidden = !d.needs_setup;
    $('dashBody').hidden = !!d.needs_setup;
    if (d.needs_setup) { syncNetFilter([]); return; }
    syncNetFilter(d.networks);
    renderChart(d.stats, d.verified);
    renderStats(d);
    renderNetBars(d.networks);
  }

  // ------------------------------------------------------------------ IP table
  const badge = (cls, text) => h('span', { class: 'badge ' + cls, text });

  function userLinks(r) {
    if (!r.users || !r.users.length) return '—';
    const out = [];
    r.users.forEach((u, i) => {
      if (i) out.push(', ');
      out.push(h('button', {
        class: 'link', type: 'button', title: `Show traffic and details for ${u}`,
        onclick: () => openUser(u, r), text: u,
      }));
    });
    return out;
  }

  function routeCell(r) {
    if (!r.route) return h('span', { class: 'muted', text: 'No matching route' });
    return h('div', {},
      h('span', { class: 'mono', text: r.route }),
      h('span', { class: 'sub', text: `table: ${r.route_table || 'main'} · ${r.route_kind === 'host' ? 'per-user host route' : 'network route'}` }));
  }

  function ipRow(r) {
    return h('tr', {},
      h('td', {}, h('span', { class: 'ip-cell' },
        h('span', { class: 'mono', text: r.ip }),
        h('button', { class: 'copy', type: 'button', title: `Copy ${r.ip}`, 'aria-label': `Copy ${r.ip}`, onclick: () => copyText(r.ip), text: 'Copy' }))),
      h('td', {}, badge('b-s-' + r.status, STATUS_LABEL[r.status] || r.status),
        r.note ? h('span', { class: 'sub', text: r.note }) : null),
      h('td', {}, userLinks(r)),
      h('td', { text: r.profile || '—' }),
      h('td', {}, r.secret_enabled === null ? '—' : badge(r.secret_enabled ? 'b-yes' : 'b-no', r.secret_enabled ? 'Enabled' : 'Disabled')),
      h('td', {}, r.session ? badge(r.session === 'online' ? 'b-online' : 'b-offline', r.session === 'online' ? 'Online' : 'Offline') : '—'),
      h('td', { class: 'mono', text: r.network }),
      h('td', {}, routeCell(r)));
  }

  // ------------------------------------------------------------------ user drawer (tx/rx)
  const DRAWER_POLL_MS = 5000;
  const drawer = { user: null, row: null, timer: null, seq: 0, opener: null };

  function fmtBits(bps) {
    const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    let v = Number(bps) || 0, i = 0;
    while (v >= 1000 && i < units.length - 1) { v /= 1000; i += 1; }
    return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(2)} ${units[i]}`;
  }
  function fmtBytes(bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let v = Number(bytes) || 0, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(2)} ${units[i]}`;
  }

  function tile(label, hint, rate, total, cls) {
    return h('div', { class: 'tile ' + cls },
      h('div', { class: 'tile-label', text: label }),
      h('div', { class: 'tile-rate', text: rate }),
      h('div', { class: 'tile-total', text: `${total} total` }),
      h('div', { class: 'muted small', text: hint }));
  }

  function renderDrawer(d) {
    const body = clear($('drawerBody'));
    $('drawerSub').textContent = d.online ? `Online · ${d.address || d.remote_address}` : 'Offline';
    const dl = (k, v) => [h('dt', { text: k }), h('dd', { text: v || '—' })];
    const r = drawer.row;

    body.append(h('div', { class: 'drawer-badges' },
      badge(d.online ? 'b-online' : 'b-offline', d.online ? 'Online' : 'Offline'),
      d.secret_enabled === null ? null : badge(d.secret_enabled ? 'b-yes' : 'b-no', d.secret_enabled ? 'Secret enabled' : 'Secret disabled')));

    if (d.traffic) {
      const t = d.traffic;
      body.append(h('div', { class: 'tiles' },
        tile('↓ Download', 'Router → user (tx)', t.rate_available ? fmtBits(t.download_bps) : 'n/a', fmtBytes(t.download_bytes), 'tile-down'),
        tile('↑ Upload', 'User → router (rx)', t.rate_available ? fmtBits(t.upload_bps) : 'n/a', fmtBytes(t.upload_bytes), 'tile-up')),
      h('p', { class: 'muted small', text: `Updated ${new Date(t.fetched_at).toLocaleTimeString()} · refreshes every ${DRAWER_POLL_MS / 1000}s while open. Totals are since this session started.` }));
    } else {
      body.append(h('div', { class: 'note', text: d.traffic_error || 'No traffic data.' }));
    }

    body.append(h('dl', { class: 'kv' },
      dl('IP address', d.address || d.remote_address),
      dl('Profile', d.profile),
      dl('MAC / caller-id', d.caller_id),
      dl('Session uptime', d.uptime),
      dl('Secret remote-address', d.remote_address),
      r && r.route ? dl('Route', `${r.route}  [table: ${r.route_table || 'main'}]`) : [],
      dl('Comment', d.comment)));
  }

  async function loadUser() {
    const user = drawer.user;
    if (!user) return;
    const seq = ++drawer.seq;
    try {
      const d = await api(`/api/user/${encodeURIComponent(user)}`);
      if (seq !== drawer.seq || user !== drawer.user) return;
      renderDrawer(d);
    } catch (e) {
      if (seq !== drawer.seq || user !== drawer.user) return;
      if (e.data && e.data.status) applyStatus(e.data.status);
      clear($('drawerBody')).append(h('div', { class: 'note', text: e.message }));
    }
  }

  function openUser(name, row) {
    drawer.user = name; drawer.row = row; drawer.opener = document.activeElement;
    $('drawerTitle').textContent = name;
    $('drawerSub').textContent = row.ip;
    clear($('drawerBody')).append(h('div', { class: 'loading' }, h('span', { class: 'spinner spinner-lg' }), ' Loading…'));
    $('userDrawer').hidden = false;
    $('drawerScrim').hidden = false;
    $('drawerClose').focus();
    clearInterval(drawer.timer);
    drawer.timer = setInterval(() => { if (!document.hidden) loadUser(); }, DRAWER_POLL_MS);
    loadUser();
  }

  function closeDrawer() {
    clearInterval(drawer.timer);
    drawer.timer = null; drawer.user = null; drawer.seq += 1;
    $('userDrawer').hidden = true;
    $('drawerScrim').hidden = true;
    if (drawer.opener && document.contains(drawer.opener)) drawer.opener.focus();
  }

  function setTableMessage(msg, withClear) {
    const e = clear($('ipEmpty'));
    e.append(msg);
    if (withClear) e.append(h('div', {}, h('button', { class: 'btn btn-sm', type: 'button', onclick: clearFilters, text: 'Clear filters' })));
    e.hidden = false;
  }

  function tableParams() {
    const p = new URLSearchParams({
      page: state.page, page_size: $('pageSize').value, sort: state.sort, dir: state.dir,
    });
    const q = $('search').value.trim();
    if (q) p.set('q', q);
    if ($('netFilter').value) p.set('network', $('netFilter').value);
    if (state.view === 'all' && $('statusFilter').value) p.set('status', $('statusFilter').value);
    return p;
  }

  async function loadTable() {
    const seq = ++state.tableSeq;
    $('ipLoading').hidden = false;
    $('ipEmpty').hidden = true;
    try {
      const d = await api(`${VIEWS[state.view].endpoint}?${tableParams()}`);
      if (seq !== state.tableSeq) return; // a newer request superseded this one
      applyStatus(d.status);
      const body = clear($('ipBody'));
      if (d.needs_setup) {
        setTableMessage(h('div', {}, h('div', { class: 'empty-title', text: 'No networks selected' }),
          'Choose the networks to monitor first.',
          h('div', {}, h('button', { class: 'btn btn-primary btn-sm', type: 'button', onclick: () => go('networks'), text: 'Select networks' }))));
        renderPager({ total: 0, page: 1, pages: 1 });
        return;
      }
      body.append(...d.rows.map(ipRow));
      const filtered = $('search').value.trim() || $('netFilter').value || (state.view === 'all' && $('statusFilter').value);
      if (!d.rows.length) setTableMessage(filtered ? 'No IPs match your filters.' : 'No IPs to show.', !!filtered);
      state.page = d.page;
      renderPager(d);
    } catch (e) {
      if (seq !== state.tableSeq) return;
      clear($('ipBody'));
      setTableMessage(e.message);
      renderPager({ total: 0, page: 1, pages: 1 });
      if (e.data && e.data.status) applyStatus(e.data.status);
      throw e;
    } finally {
      if (seq === state.tableSeq) $('ipLoading').hidden = true;
    }
  }

  function renderPager(d) {
    const size = Number($('pageSize').value);
    const from = d.total ? (d.page - 1) * size + 1 : 0;
    const to = Math.min(d.total, d.page * size);
    $('pageInfo').textContent = `${fmtNum(from)}–${fmtNum(to)} of ${fmtNum(d.total)}`;
    $('pageNum').textContent = `Page ${d.page} of ${d.pages}`;
    $('pFirst').disabled = $('pPrev').disabled = d.page <= 1;
    $('pNext').disabled = $('pLast').disabled = d.page >= d.pages;
    state.pages = d.pages;
  }

  function updateSortArrows() {
    document.querySelectorAll('#ipTable .sort').forEach((b) => {
      b.classList.toggle('asc', b.dataset.sort === state.sort && state.dir === 'asc');
      b.classList.toggle('desc', b.dataset.sort === state.sort && state.dir === 'desc');
    });
  }

  function clearFilters() {
    $('search').value = '';
    $('netFilter').value = '';
    $('statusFilter').value = '';
    ['search', 'subnet', 'status'].forEach((k) => prefs.set(k, ''));
    state.page = 1;
    refresh({ silent: true });
  }

  // CSV export (fetch so stale/unverified refusals show a clear message)
  async function exportCsv(scope) {
    try {
      const res = await fetch(`/api/export.csv?scope=${scope}`, { credentials: 'same-origin', headers: { 'X-CSRF-Token': CSRF } });
      if (!res.ok) {
        let msg = `Export failed (${res.status}).`;
        try { msg = (await res.json()).error || msg; } catch { /* ignore */ }
        toast(msg, 'err');
        return;
      }
      const blob = await res.blob();
      const m = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '');
      const a = h('a', { href: URL.createObjectURL(blob), download: m ? m[1] : `ips-${scope}.csv` });
      document.body.append(a);
      a.click();
      setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
      toast(`Exported ${scope} IPs${res.headers.get('X-Data-Stale') === '1' ? ' (stale data)' : ''}.`);
    } catch {
      toast('Export failed: cannot reach the server.', 'err');
    }
  }

  // ------------------------------------------------------------------ reports
  async function loadReports() {
    const d = await api('/api/reports');
    applyStatus(d.status);
    const oor = clear($('oorBody')), dis = clear($('disBody'));
    d.out_of_range.forEach((r) => oor.append(h('tr', {},
      h('td', { text: r.username || '—' }), h('td', { class: 'mono', text: r.remote_address }),
      h('td', { text: r.profile || '—' }),
      h('td', {}, badge(r.disabled ? 'b-no' : 'b-yes', r.disabled ? 'Disabled' : 'Enabled')),
      h('td', { text: r.reason }), h('td', { text: r.comment || '—' }))));
    d.disabled_secrets.forEach((r) => dis.append(h('tr', {},
      h('td', { text: r.username || '—' }), h('td', { class: 'mono', text: r.remote_address || '—' }),
      h('td', { text: r.profile || '—' }),
      h('td', {}, badge(r.in_monitored_range ? 'b-yes' : 'b-no', r.in_monitored_range ? 'Yes' : 'No')),
      h('td', {}, badge(r.has_active_session ? 'b-online' : 'b-offline', r.has_active_session ? 'Online' : 'No')),
      h('td', { text: r.comment || '—' }))));
    $('oorCount').textContent = d.out_of_range.length;
    $('disCount').textContent = d.disabled_secrets.length;
    $('oorEmpty').hidden = d.out_of_range.length > 0;
    $('disEmpty').hidden = d.disabled_secrets.length > 0;
    $('oorEmpty').textContent = d.needs_setup ? 'Select networks to monitor to see this report.' : 'No out-of-range assignments.';
  }

  // ------------------------------------------------------------------ networks editor
  const usable = (cidr) => {
    const p = Number(cidr.split('/')[1]);
    return p >= 31 ? 2 ** (32 - p) : 2 ** (32 - p) - 2;
  };

  function updateAddrSummary() {
    const total = [...state.selected].reduce((n, c) => n + usable(c), 0);
    const cap = Number($('maxAddr').value) || 0;
    const over = cap && total > cap;
    $('addrSummary').textContent = `${state.selected.size} network(s), up to ${fmtNum(total)} addresses${cap ? ` (limit ${fmtNum(cap)})` : ''}${over ? ': over the limit' : ''}`;
  }

  function markDirty() {
    state.netsDirty = true;
    $('saveHint').textContent = 'Unsaved changes';
    updateAddrSummary();
  }

  function renderManual() {
    const ul = clear($('manualList'));
    state.manual.forEach((n) => ul.append(h('li', { class: 'chip' }, n,
      h('button', { type: 'button', 'aria-label': `Remove ${n}`, text: '×', onclick: () => {
        state.manual = state.manual.filter((x) => x !== n);
        state.selected.delete(n);
        renderManual(); markDirty();
      } }))));
  }

  function renderCandidates() {
    const body = clear($('candBody'));
    state.cands.forEach((c) => {
      const cb = h('input', { type: 'checkbox', 'aria-label': `Monitor ${c.network}` });
      cb.checked = state.selected.has(c.network);
      cb.addEventListener('change', () => {
        if (cb.checked) state.selected.add(c.network); else state.selected.delete(c.network);
        markDirty();
      });
      body.append(h('tr', {},
        h('td', { class: 'col-check' }, cb), h('td', { class: 'mono', text: c.network }),
        h('td', { text: fmtNum(c.addresses) }), h('td', { text: c.gateway || '—' }), h('td', { text: c.comment || '—' }),
        h('td', {}, c.dynamic ? h('span', { class: 'tag', text: 'dynamic' }) : null, c.disabled ? h('span', { class: 'tag', text: 'disabled' }) : null)));
    });
    $('candEmpty').hidden = state.cands.length > 0;
  }

  async function loadNetworks() {
    const d = await api('/api/networks');
    applyStatus(d.status);
    state.cands = d.candidates;
    state.manual = [...d.manual];
    state.selected = new Set(d.selected);
    $('reservedText').value = d.reserved.join('\n');
    $('maxAddr').value = d.max_addresses;
    state.netsDirty = false;
    $('saveHint').textContent = '';
    renderCandidates(); renderManual(); updateAddrSummary();
  }

  function addManual() {
    const raw = $('manualNet').value.trim();
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(raw);
    if (!m || m.slice(1, 5).some((o) => Number(o) > 255) || Number(m[5]) < 1 || Number(m[5]) > 32) {
      toast('Enter an IPv4 network like 10.20.0.0/22.', 'err');
      return;
    }
    if (state.cands.some((c) => c.network === raw)) state.selected.add(raw);
    else if (!state.manual.includes(raw)) { state.manual.push(raw); state.selected.add(raw); }
    $('manualNet').value = '';
    renderCandidates(); renderManual(); markDirty();
  }

  async function saveNetworks() {
    const reserved = $('reservedText').value.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
    const btn = $('saveNets');
    btn.disabled = true;
    try {
      const r = await api('/api/networks', { method: 'PUT', body: {
        networks: [...state.selected], reserved, max_addresses: Number($('maxAddr').value),
      } });
      toast(`Saved: ${r.networks.length} network(s), ${fmtNum(r.selected_addresses)} addresses.`);
      state.netsDirty = false;
      await loadNetworks();
    } catch (e) {
      toast(e.message, 'err');
    } finally {
      btn.disabled = false;
    }
  }

  // ------------------------------------------------------------------ navigation / refresh
  function go(view, opts = {}) {
    if (opts.status !== undefined) { $('statusFilter').value = opts.status || ''; prefs.set('status', opts.status || ''); state.page = 1; }
    if (location.hash === '#' + view) showView(view); else location.hash = view;
  }

  function showView(view) {
    if (!VIEWS[view]) view = 'dashboard';
    if (drawer.user) closeDrawer();
    state.view = view;
    document.querySelectorAll('.view').forEach((s) => { s.hidden = s.id !== VIEWS[view].section; });
    document.querySelectorAll('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
    $('pageTitle').textContent = VIEWS[view].title;
    document.title = `${VIEWS[view].title} · PPPoE IP Manager`;
    $('statusWrap').hidden = view !== 'all';
    $('ipsFreeNote').hidden = view !== 'free';
    state.page = 1;
    closeMenu();
    refresh({ silent: true, fromNav: true });
  }

  async function loadCurrent(silent) {
    const v = state.view;
    if (v === 'reports') return loadReports();
    if (v === 'networks') {
      if (state.netsDirty && silent) { const s = await api('/api/status'); applyStatus(s.status); return undefined; }
      return loadNetworks();
    }
    await loadDashboard();
    if (VIEWS[v].endpoint) await loadTable();
    return undefined;
  }

  function setBusy(on) {
    $('refreshSpin').hidden = !on;
    $('refreshBtn').disabled = on;
    $('refreshLabel').textContent = on ? 'Refreshing…' : 'Refresh';
  }

  async function refresh({ manual = false, silent = false, fromNav = false } = {}) {
    if (state.inflight) { // never overlap requests
      if (manual) toast('A refresh is already running.');
      if (fromNav) state.queued = true; // load the newly opened view once the current run ends
      return;
    }
    state.inflight = true;
    setBusy(true);
    try {
      if (manual) {
        const r = await api('/api/sync', { method: 'POST' });
        applyStatus(r.status);
        if (r.error) toast(`Router sync failed: ${r.error}`, 'err'); else toast('Synchronized with router.');
      }
      await loadCurrent(silent && !manual);
    } catch (e) {
      showFatal(e, silent && !manual);
    } finally {
      state.inflight = false;
      setBusy(false);
      if (state.queued) { state.queued = false; refresh({ silent: true }); }
    }
  }

  let timer = null;
  function setAutoRefresh(on) {
    prefs.set('autoRefresh', on);
    clearInterval(timer);
    timer = on ? setInterval(() => { if (!document.hidden) refresh({ silent: true }); }, REFRESH_MS) : null;
  }

  function closeMenu() {
    $('sidebar').classList.remove('open');
    $('scrim').hidden = true;
    $('menuBtn').setAttribute('aria-expanded', 'false');
  }

  // ------------------------------------------------------------------ wiring
  function init() {
    $('pageSize').value = ['25', '50', '100', '250'].includes(prefs.get('pageSize')) ? prefs.get('pageSize') : '50';
    $('search').value = prefs.get('search', '');
    $('statusFilter').value = prefs.get('status', '') || '';
    $('autoRefresh').checked = prefs.get('autoRefresh', 'true') !== 'false';

    document.querySelectorAll('.nav-item').forEach((b) => b.addEventListener('click', () => go(b.dataset.view)));
    document.querySelectorAll('[data-goto]').forEach((b) => b.addEventListener('click', () => go(b.dataset.goto)));
    document.querySelectorAll('[data-export]').forEach((b) => b.addEventListener('click', () => exportCsv(b.dataset.export)));
    window.addEventListener('hashchange', () => showView(location.hash.slice(1)));

    $('refreshBtn').addEventListener('click', () => refresh({ manual: true }));
    $('autoRefresh').addEventListener('change', (e) => setAutoRefresh(e.target.checked));
    $('themeBtn').addEventListener('click', () => {
      const next = effectiveDark() ? 'light' : 'dark';
      applyTheme(next); prefs.set('theme', next);
      if (state.chart) { // recolor from the new theme's variables
        state.chart.data.datasets[0].backgroundColor = [cssVar('--c-assigned'), cssVar('--c-free'), cssVar('--c-other')];
        state.chart.update();
      }
    });
    $('menuBtn').addEventListener('click', () => {
      const open = !$('sidebar').classList.contains('open');
      $('sidebar').classList.toggle('open', open);
      $('scrim').hidden = !open;
      $('menuBtn').setAttribute('aria-expanded', String(open));
    });
    $('scrim').addEventListener('click', closeMenu);
    $('drawerClose').addEventListener('click', closeDrawer);
    $('drawerScrim').addEventListener('click', closeDrawer);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('userDrawer').hidden) closeDrawer(); });

    let debounce = null;
    $('search').addEventListener('input', () => {
      prefs.set('search', $('search').value);
      clearTimeout(debounce);
      debounce = setTimeout(() => { state.page = 1; loadTable().catch((e) => showFatal(e, true)); }, 250);
    });
    $('statusFilter').addEventListener('change', () => { prefs.set('status', $('statusFilter').value); state.page = 1; loadTable().catch((e) => showFatal(e, true)); });
    $('netFilter').addEventListener('change', () => { prefs.set('subnet', $('netFilter').value); state.page = 1; loadTable().catch((e) => showFatal(e, true)); });
    $('pageSize').addEventListener('change', () => { prefs.set('pageSize', $('pageSize').value); state.page = 1; loadTable().catch((e) => showFatal(e, true)); });

    document.querySelectorAll('#ipTable .sort').forEach((b) => b.addEventListener('click', () => {
      state.dir = state.sort === b.dataset.sort && state.dir === 'asc' ? 'desc' : 'asc';
      state.sort = b.dataset.sort;
      state.page = 1;
      updateSortArrows();
      loadTable().catch((e) => showFatal(e, true));
    }));
    const page = (n) => { state.page = Math.max(1, Math.min(state.pages || 1, n)); loadTable().catch((e) => showFatal(e, true)); };
    $('pFirst').addEventListener('click', () => page(1));
    $('pPrev').addEventListener('click', () => page(state.page - 1));
    $('pNext').addEventListener('click', () => page(state.page + 1));
    $('pLast').addEventListener('click', () => page(state.pages || 1));

    $('manualAdd').addEventListener('click', addManual);
    $('manualNet').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addManual(); } });
    $('reservedText').addEventListener('input', markDirty);
    $('maxAddr').addEventListener('input', markDirty);
    $('saveNets').addEventListener('click', saveNetworks);

    updateSortArrows();
    setAutoRefresh($('autoRefresh').checked);
    showView(location.hash.slice(1) || 'dashboard');
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
