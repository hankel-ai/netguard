// NetGuard — multi-target frontend

// === API helper ===

async function api(path, method = 'GET', body = null) {
    const opts = { method, headers: {} };
    if (body) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
    }
    try {
        const res = await fetch(path, opts);
        if (res.status === 401) { window.location.href = '/'; return null; }
        const data = await res.json();
        if (!res.ok) return { _error: true, detail: data.detail || 'Server error' };
        return data;
    } catch (e) {
        return { _error: true, detail: 'Network error' };
    }
}

const DAY_LABELS = {
    weekday: 'Weekdays', weekend: 'Weekend',
    mon: 'Mon', tue: 'Tue', wed: 'Wed', thu: 'Thu', fri: 'Fri', sat: 'Sat', sun: 'Sun'
};

function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function fmtBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
}

function fmtRate(bps) {
    if (bps < 1024) return bps + ' B/s';
    if (bps < 1048576) return (bps / 1024).toFixed(1) + ' KB/s';
    return (bps / 1048576).toFixed(1) + ' MB/s';
}

function fmt12(time24) {
    if (!time24) return '';
    const [h, m] = time24.split(':').map(Number);
    const suffix = h >= 12 ? 'PM' : 'AM';
    const h12 = h % 12 || 12;
    return `${h12}:${String(m).padStart(2, '0')} ${suffix}`;
}

// === Pi-hole state ===
let _piholeConnected = false;

async function checkPiholeStatus() {
    const status = await api('/api/pihole/status');
    if (!status || status._error) return;
    _piholeConnected = status.configured && status.connected;
    const badge = document.getElementById('pihole-badge');
    if (status.configured) {
        badge.hidden = false;
        badge.className = 'pihole-badge ' + (_piholeConnected ? 'connected' : 'disconnected');
        badge.textContent = _piholeConnected ? 'Pi-hole connected' : 'Pi-hole disconnected';
    }
}

// === Tabs ===

document.querySelector('.tabs').addEventListener('click', (e) => {
    const tab = e.target.closest('.tab');
    if (!tab) return;
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
});

// === Search ===

function matchesSearch(query, ...fields) {
    if (!query) return true;
    const q = query.toLowerCase();
    return fields.some(f => f && f.toLowerCase().includes(q));
}

document.getElementById('search-targets').addEventListener('input', () => renderTargets());
document.getElementById('search-scan').addEventListener('input', () => renderScanList());

// === Targets ===

let _targets = [];

async function refreshTargets() {
    const targets = await api('/api/targets');
    if (!targets || targets._error) return;
    _targets = targets;
    renderTargets();
}

function renderTargets() {
    const query = document.getElementById('search-targets').value;
    const list = document.getElementById('targets-list');

    const filtered = _targets.filter(t =>
        matchesSearch(query, t.hostname, t.target_ip || t.ip, t.mac, t.vendor, t.device_type)
    );

    if (_targets.length === 0) {
        list.innerHTML = '<div class="card empty">No targets configured. Switch to LAN Devices to scan and add.</div>';
        return;
    }

    if (filtered.length === 0) {
        list.innerHTML = '<div class="card empty">No targets match your search.</div>';
        return;
    }

    list.innerHTML = filtered.map(renderTargetCard).join('');
}

function renderTargetCard(t) {
    const blocked = t.is_blocking;
    const dnsBlocked = t.dns_blocked;
    const monitoring = t.is_monitoring;
    const statusClass = blocked ? 'blocked' : 'unblocked';
    const statusText = blocked ? 'BLOCKED' : 'UNBLOCKED';
    const displayName = t.hostname || t.device_type || t.vendor || 'Unknown Device';
    const ip = t.target_ip || t.ip || '\u2014';
    const hasOverride = t.override !== 'none';
    const hasSchedules = t.schedules && t.schedules.length > 0;
    const hasEnabledSchedules = hasSchedules && t.schedules.some(s => s.enabled);

    let scheduleSummary = '';
    if (hasSchedules) {
        const enabled = t.schedules.filter(s => s.enabled);
        if (enabled.length > 0) {
            scheduleSummary = enabled.map(s =>
                `${DAY_LABELS[s.day_of_week] || s.day_of_week} ${fmt12(s.start_time)}\u2013${fmt12(s.end_time)}`
            ).join(', ');
        } else {
            scheduleSummary = `${t.schedules.length} schedule(s), all disabled`;
        }
    }

    let scheduleClass = 'target-schedule';
    if (hasOverride) {
        scheduleClass += ' schedule-muted';
    } else if (hasEnabledSchedules) {
        scheduleClass += blocked ? ' schedule-red' : ' schedule-green';
    }

    const blockPressed = t.override === 'block';
    const unblockPressed = t.override === 'unblock';

    const desc = t.description || '';

    let trafficHtml = '';
    if (monitoring && t.traffic) {
        const s = t.traffic;
        const active = (s.tx_rate > 0 || s.rx_rate > 0);
        trafficHtml = `
        <div class="traffic-stats${active ? ' traffic-active' : ''}">
            <span class="traffic-rate">&uarr; ${fmtRate(s.tx_rate)}</span>
            <span class="traffic-rate">&darr; ${fmtRate(s.rx_rate)}</span>
            <span class="traffic-total dim">${fmtBytes(s.tx_bytes)} up / ${fmtBytes(s.rx_bytes)} down</span>
        </div>`;
    } else if (monitoring) {
        trafficHtml = '<div class="traffic-stats dim">Monitoring... waiting for data</div>';
    }

    // Status badges (online + ARP block + optional DNS)
    const online = t.is_online;
    const onlineClass = online ? 'online' : 'offline';
    const onlineText = online ? 'ONLINE' : 'OFFLINE';
    let badgesHtml = `<div class="status-badge ${onlineClass}"><span class="dot"></span> ${onlineText}</div>`;
    badgesHtml += `<div class="status-badge ${statusClass}"><span class="dot"></span> ${statusText}</div>`;
    if (dnsBlocked) {
        badgesHtml += `<div class="status-badge dns-blocked"><span class="dot"></span> DNS</div>`;
    }

    // Pi-hole buttons (only when connected)
    let piholeButtons = '';
    if (_piholeConnected) {
        piholeButtons = `
            <button class="btn btn-sm${dnsBlocked ? ' btn-dns-active' : ' btn-secondary'}" data-action="${dnsBlocked ? 'dns-unblock' : 'dns-block'}">${dnsBlocked ? 'DNS BLOCKED' : 'DNS BLOCK'}</button>
            <button class="btn btn-sm btn-secondary" data-action="dns-queries" data-name="${esc(displayName)}">DNS</button>`;
    }

    return `
    <div class="card target-card" data-id="${t.id}">
        <div class="target-header">
            <div class="target-info">
                <div class="target-name-row">
                    <span class="target-name">${esc(displayName)}</span>
                    <span class="target-desc" data-action="edit-desc">${desc ? esc(desc) : ''}</span>
                </div>
                <div class="target-details">${esc(ip)} &middot; ${esc(t.mac)}${t.vendor ? ` &middot; ${esc(t.vendor)}` : ''}${t.device_type && t.device_type !== t.vendor ? ` (${esc(t.device_type)})` : ''}</div>
            </div>
            <div class="status-badges">
                ${badgesHtml}
            </div>
        </div>${trafficHtml}
        <div class="${scheduleClass}" data-action="schedule" data-name="${esc(displayName)}">
            ${scheduleSummary
                ? `<span class="schedule-icon">\u{1F551}</span> ${esc(scheduleSummary)}`
                : '<span class="schedule-icon">\u{1F551}</span> No schedule \u2014 tap to add'
            }
        </div>
        <div class="target-actions">
            <button class="btn btn-danger btn-sm${blockPressed ? ' btn-pressed' : ''}" data-action="block"${blockPressed ? ' disabled' : ''}>BLOCK</button>
            <button class="btn btn-success btn-sm${unblockPressed ? ' btn-pressed' : ''}" data-action="unblock"${unblockPressed ? ' disabled' : ''}>UNBLOCK</button>
            ${hasOverride ? '<button class="btn btn-secondary btn-sm" data-action="clear-override">CLEAR</button>' : ''}
            <button class="btn btn-sm${monitoring ? ' btn-monitor-active' : ' btn-secondary'}" data-action="${monitoring ? 'unmonitor' : 'monitor'}">${monitoring ? 'MONITORING' : 'MONITOR'}</button>
            ${piholeButtons}
            <button class="btn btn-sm btn-danger" data-action="delete" data-name="${esc(displayName)}">\u2715</button>
        </div>
    </div>`;
}

// Event delegation for target cards
document.getElementById('targets-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const card = btn.closest('[data-id]');
    if (!card) return;
    const id = card.dataset.id;
    const action = btn.dataset.action;

    if (action === 'edit-desc') {
        const input = btn.querySelector('.desc-input');
        if (input) { input.focus(); return; }
        const target = _targets.find(t => String(t.id) === id);
        const current = target?.description || '';
        btn.innerHTML = `<input class="desc-input" type="text" value="${esc(current)}" placeholder="Add description...">`;
        const newInput = btn.querySelector('.desc-input');
        newInput.focus();
        const save = async () => {
            const val = newInput.value.trim();
            await api(`/api/targets/${id}/description`, 'PATCH', { description: val });
            await refreshTargets();
        };
        newInput.addEventListener('blur', save);
        newInput.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter') newInput.blur();
            if (ev.key === 'Escape') { refreshTargets(); }
        });
        return;
    }
    if (action === 'schedule') {
        openScheduleModal(id, btn.dataset.name);
        return;
    }
    if (action === 'dns-queries') {
        openDnsModal(id, btn.dataset.name);
        return;
    }
    if (action === 'delete') {
        const name = btn.dataset.name || 'this target';
        if (!confirm(`Remove "${name}"? This will unblock it and delete all its schedules.`)) return;
        await api(`/api/targets/${id}`, 'DELETE');
        await refreshTargets();
        await refreshLog();
        await loadCachedDevices();
        return;
    } else {
        btn.disabled = true;
        btn.textContent = '...';
        await api(`/api/targets/${id}/${action}`, 'POST');
    }
    await refreshTargets();
    await refreshLog();
});

// === Schedule Modal ===

let _scheduleTargetId = null;
let _editingRuleId = null;

// Time picker helpers
function to12(time24) {
    const [h, m] = time24.split(':').map(Number);
    return { h: h % 12 || 12, m, p: h >= 12 ? 'PM' : 'AM' };
}

function to24(h, m, p) {
    let h24 = h % 12;
    if (p === 'PM') h24 += 12;
    return `${String(h24).padStart(2, '0')}:${String(m).padStart(2, '0')}`;
}

function initTimePickers() {
    ['rule-start-h', 'rule-end-h'].forEach(id => {
        const sel = document.getElementById(id);
        sel.innerHTML = '';
        for (let h = 1; h <= 12; h++) sel.add(new Option(h, h));
    });
    ['rule-start-m', 'rule-end-m'].forEach(id => {
        const sel = document.getElementById(id);
        sel.innerHTML = '';
        for (let m = 0; m < 60; m += 5) sel.add(new Option(String(m).padStart(2, '0'), m));
    });
    ['rule-start-p', 'rule-end-p'].forEach(id => {
        const sel = document.getElementById(id);
        sel.innerHTML = '';
        sel.add(new Option('AM', 'AM'));
        sel.add(new Option('PM', 'PM'));
    });
}

function setTimePicker(prefix, time24) {
    const t = to12(time24);
    document.getElementById(prefix + '-h').value = t.h;
    // Snap to nearest 5-min
    const snapped = Math.round(t.m / 5) * 5;
    document.getElementById(prefix + '-m').value = snapped >= 60 ? 55 : snapped;
    document.getElementById(prefix + '-p').value = t.p;
}

function getTimePicker(prefix) {
    const h = parseInt(document.getElementById(prefix + '-h').value);
    const m = parseInt(document.getElementById(prefix + '-m').value);
    const p = document.getElementById(prefix + '-p').value;
    return to24(h, m, p);
}

function resetScheduleForm() {
    _editingRuleId = null;
    document.getElementById('rule-day').value = 'weekday';
    setTimePicker('rule-start', '22:00');
    setTimePicker('rule-end', '07:00');
    document.getElementById('schedule-submit-btn').textContent = '+ Add';
    document.getElementById('schedule-cancel-btn').hidden = true;
}

function openScheduleModal(targetId, name) {
    _scheduleTargetId = targetId;
    document.getElementById('schedule-modal-title').textContent = `Schedule: ${name}`;
    document.getElementById('schedule-modal').hidden = false;
    resetScheduleForm();
    refreshScheduleModal();
}

function closeScheduleModal() {
    document.getElementById('schedule-modal').hidden = true;
    _scheduleTargetId = null;
    _editingRuleId = null;
}

document.getElementById('btn-close-schedule').addEventListener('click', closeScheduleModal);

document.getElementById('schedule-cancel-btn').addEventListener('click', resetScheduleForm);

async function refreshScheduleModal() {
    if (!_scheduleTargetId) return;
    const rules = await api(`/api/targets/${_scheduleTargetId}/schedules`);
    if (!rules || rules._error) return;
    const list = document.getElementById('schedule-rules-list');

    if (rules.length === 0) {
        list.innerHTML = '<p class="dim">No schedules yet. Add one below.</p>';
        return;
    }

    list.innerHTML = rules.map(r => `
        <div class="rule-item${_editingRuleId === r.id ? ' editing' : ''}">
            <span class="rule-label ${r.enabled ? '' : 'disabled'}">
                ${DAY_LABELS[r.day_of_week] || r.day_of_week} ${fmt12(r.start_time)}\u2013${fmt12(r.end_time)}
            </span>
            <div class="rule-actions">
                <button class="btn btn-sm btn-secondary" data-rule-action="edit" data-rule-id="${r.id}"
                    data-day="${r.day_of_week}" data-start="${r.start_time}" data-end="${r.end_time}">\u270E</button>
                <button class="btn btn-sm btn-secondary" data-rule-action="toggle" data-rule-id="${r.id}">${r.enabled ? '\u2611' : '\u2610'}</button>
                <button class="btn btn-sm btn-danger" data-rule-action="delete" data-rule-id="${r.id}">\u2715</button>
            </div>
        </div>
    `).join('');
}

document.getElementById('schedule-rules-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-rule-action]');
    if (!btn) return;
    const ruleId = btn.dataset.ruleId;
    const action = btn.dataset.ruleAction;

    if (action === 'edit') {
        _editingRuleId = parseInt(ruleId);
        document.getElementById('rule-day').value = btn.dataset.day;
        setTimePicker('rule-start', btn.dataset.start);
        setTimePicker('rule-end', btn.dataset.end);
        document.getElementById('schedule-submit-btn').textContent = 'Save';
        document.getElementById('schedule-cancel-btn').hidden = false;
        refreshScheduleModal();
        return;
    }
    if (action === 'toggle') {
        await api(`/api/schedules/${ruleId}/toggle`, 'PATCH');
    } else if (action === 'delete') {
        await api(`/api/schedules/${ruleId}`, 'DELETE');
        if (_editingRuleId === parseInt(ruleId)) resetScheduleForm();
    }
    await refreshScheduleModal();
    await refreshTargets();
});

document.getElementById('schedule-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!_scheduleTargetId) return;
    const day = document.getElementById('rule-day').value;
    const start = getTimePicker('rule-start');
    const end = getTimePicker('rule-end');

    if (_editingRuleId) {
        await api(`/api/schedules/${_editingRuleId}`, 'PUT', {
            day_of_week: day, start_time: start, end_time: end,
        });
    } else {
        await api(`/api/targets/${_scheduleTargetId}/schedules`, 'POST', {
            day_of_week: day, start_time: start, end_time: end,
        });
    }
    resetScheduleForm();
    await refreshScheduleModal();
    await refreshTargets();
});

// === DNS Queries Modal ===

let _dnsTargetId = null;
let _dnsIp = null;
let _dnsRefreshTimer = null;

function openDnsModal(targetId, name) {
    _dnsTargetId = targetId;
    _dnsIp = null;
    document.getElementById('dns-modal-title').textContent = `DNS: ${name}`;
    document.getElementById('dns-modal').hidden = false;
    document.getElementById('dns-search').value = '';
    refreshDnsQueries();
    _dnsRefreshTimer = setInterval(refreshDnsQueries, 10000);
}

function openDnsModalByIp(ip, name) {
    _dnsTargetId = null;
    _dnsIp = ip;
    document.getElementById('dns-modal-title').textContent = `DNS: ${name || ip}`;
    document.getElementById('dns-modal').hidden = false;
    document.getElementById('dns-search').value = '';
    refreshDnsQueries();
    _dnsRefreshTimer = setInterval(refreshDnsQueries, 10000);
}

function closeDnsModal() {
    document.getElementById('dns-modal').hidden = true;
    _dnsTargetId = null;
    _dnsIp = null;
    if (_dnsRefreshTimer) { clearInterval(_dnsRefreshTimer); _dnsRefreshTimer = null; }
}

document.getElementById('btn-close-dns').addEventListener('click', closeDnsModal);
document.getElementById('dns-search').addEventListener('input', () => renderDnsQueries());

let _dnsQueries = [];

async function refreshDnsQueries() {
    if (!_dnsTargetId && !_dnsIp) return;
    const url = _dnsTargetId
        ? `/api/targets/${_dnsTargetId}/dns-queries`
        : `/api/dns-queries?ip=${encodeURIComponent(_dnsIp)}`;
    const result = await api(url);
    if (!result || result._error || !result.ok) return;
    _dnsQueries = result.queries || [];
    renderDnsQueries();
}

function dnsStatusClass(status) {
    if (!status) return '';
    const s = String(status).toLowerCase();
    if (s.includes('forward') || s.includes('answer') || s === '2' || s === '3') return 'forwarded';
    if (s.includes('block') || s.includes('deny') || s.includes('gravity') || s === '1') return 'blocked';
    if (s.includes('cache') || s === '4') return 'cached';
    return '';
}

function dnsStatusLabel(status) {
    if (!status) return '';
    const s = String(status).toLowerCase();
    if (s.includes('forward') || s === '2' || s === '3') return 'forwarded';
    if (s.includes('block') || s.includes('deny') || s.includes('gravity') || s === '1') return 'blocked';
    if (s.includes('cache') || s === '4') return 'cached';
    return s;
}

function renderDnsQueries() {
    const filter = (document.getElementById('dns-search').value || '').toLowerCase();
    const list = document.getElementById('dns-query-list');

    const filtered = _dnsQueries.filter(q => {
        const domain = q.domain || q.name || '';
        return !filter || domain.toLowerCase().includes(filter);
    });

    if (filtered.length === 0) {
        list.innerHTML = '<p class="dim">No DNS queries found.</p>';
        return;
    }

    list.innerHTML = filtered.slice(0, 200).map(q => {
        const domain = q.domain || q.name || '?';
        const type = q.type || '';
        const status = q.status || '';
        const ts = q.timestamp || q.time || 0;
        const date = typeof ts === 'number' && ts > 0 ? new Date(ts * 1000) : null;
        const timeStr = date ? date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true }) : '';
        const sc = dnsStatusClass(status);
        const sl = dnsStatusLabel(status);
        return `
        <div class="dns-query-item">
            <span class="dns-query-time">${timeStr}</span>
            <span class="dns-query-domain">${esc(domain)}</span>
            <span class="dns-query-type">${esc(type)}</span>
            <span class="dns-query-status ${sc}">${sl}</span>
        </div>`;
    }).join('');
}

// === LAN Scan Tab ===

let _scanResults = [];
let _scanning = false;

document.getElementById('btn-scan').addEventListener('click', doScan);

async function loadCachedDevices() {
    const devices = await api('/api/lan-devices');
    if (!devices || devices._error) return;
    _scanResults = devices;
    updateScanStatus();
    renderScanList();
}

function updateScanStatus() {
    const status = document.getElementById('scan-status');
    if (_scanResults.length === 0) {
        status.textContent = 'No cached devices. Hit "Scan Now" to discover.';
        return;
    }
    const count = _scanResults.length;
    const added = _scanResults.filter(d => d.is_target).length;
    status.textContent = `${count} device${count !== 1 ? 's' : ''} (${added} already added)`;
}

async function doScan() {
    if (_scanning) return;
    _scanning = true;
    const btn = document.getElementById('btn-scan');
    const status = document.getElementById('scan-status');
    btn.disabled = true;
    btn.textContent = 'Scanning...';
    status.textContent = 'Scanning network...';

    const rebuild = document.getElementById('chk-rebuild')?.checked;
    const url = rebuild ? '/api/scan?rebuild=true' : '/api/scan';
    const devices = await api(url, 'POST');
    _scanning = false;
    btn.disabled = false;
    btn.textContent = 'Scan Now';

    if (!devices || devices._error) {
        status.textContent = 'Scan failed. Try again.';
        return;
    }

    _scanResults = devices;
    updateScanStatus();
    renderScanList();
}

function renderScanList() {
    const query = document.getElementById('search-scan').value;
    const el = document.getElementById('scan-list');

    if (_scanResults.length === 0) {
        el.innerHTML = '<div class="card empty">No devices. Hit "Scan Now" to discover devices on your network.</div>';
        return;
    }

    const filtered = _scanResults.filter(d =>
        matchesSearch(query, d.hostname, d.ip, d.mac, d.vendor, d.device_type)
    );

    if (filtered.length === 0) {
        el.innerHTML = '<div class="card empty">No devices match your search.</div>';
        return;
    }

    el.innerHTML = filtered.map((d, _) => {
        const realIdx = _scanResults.indexOf(d);
        const name = d.hostname || d.device_type || d.vendor || null;
        const vendorTag = d.vendor && d.vendor !== name ? ` &middot; ${esc(d.vendor)}` : '';
        const typeTag = d.device_type && d.device_type !== name ? ` (${esc(d.device_type)})` : '';
        const online = d.is_online;
        const onlineDot = `<span class="online-dot ${online ? 'on' : 'off'}"></span>`;
        const dnsBtn = _piholeConnected && d.ip
            ? `<button class="btn btn-sm btn-secondary" data-dns-ip="${esc(d.ip)}" data-dns-name="${esc(name || d.ip)}">DNS</button>`
            : '';
        return `
        <div class="scan-device ${d.is_target ? 'already-added' : ''}">
            <div class="scan-device-info">
                <div class="scan-device-name">${onlineDot}${name ? esc(name) : '<em>Unknown</em>'}</div>
                <div class="scan-device-details">${esc(d.ip)} &middot; ${esc(d.mac)}${vendorTag}${typeTag}</div>
            </div>
            <div class="scan-device-actions">
                ${dnsBtn}
                ${d.is_target
                    ? '<span class="dim">Added</span>'
                    : `<button class="btn btn-primary btn-sm" data-scan-idx="${realIdx}">Add</button>`
                }
            </div>
        </div>`;
    }).join('');
}

// Event delegation for scan results
document.getElementById('scan-list').addEventListener('click', async (e) => {
    const dnsBtn = e.target.closest('[data-dns-ip]');
    if (dnsBtn) {
        openDnsModalByIp(dnsBtn.dataset.dnsIp, dnsBtn.dataset.dnsName);
        return;
    }
    const btn = e.target.closest('[data-scan-idx]');
    if (!btn) return;
    const idx = parseInt(btn.dataset.scanIdx);
    const d = _scanResults[idx];
    if (!d) return;

    btn.disabled = true;
    btn.textContent = 'Adding...';
    const result = await api('/api/targets', 'POST', {
        mac: d.mac, ip: d.ip || null, hostname: d.hostname || null,
    });
    // Change detected — ask user to confirm
    if (result && result.confirm) {
        const msg = 'Changes detected:\n' + result.changes.join('\n') + '\n\nAdd anyway?';
        if (confirm(msg)) {
            const forced = await api('/api/targets', 'POST', {
                mac: result.mac, ip: result.ip, hostname: result.hostname, force: true,
            });
            if (forced && !forced._error && forced.ok) {
                d.is_target = true;
                renderScanList();
                await refreshTargets();
                await refreshLog();
                return;
            }
            btn.textContent = forced?.error || 'Failed';
            btn.disabled = false;
            return;
        }
        btn.textContent = 'Add';
        btn.disabled = false;
        return;
    }
    if (result && !result._error && result.ok) {
        d.is_target = true;
        renderScanList();
        await refreshTargets();
        await refreshLog();
    } else {
        btn.textContent = result?.error || 'Failed';
        btn.disabled = false;
    }
});

// === Manual Add ===

document.getElementById('add-target-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ipInput = document.getElementById('add-ip');
    const ip = ipInput.value.trim();
    if (!ip) return;

    const btn = e.target.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Resolving...';

    const result = await api('/api/targets', 'POST', { ip });

    // Change detected — ask user to confirm
    if (result && result.confirm) {
        btn.disabled = false;
        btn.textContent = 'Add';
        const msg = 'Changes detected:\n' + result.changes.join('\n') + '\n\nAdd anyway?';
        if (confirm(msg)) {
            btn.disabled = true;
            btn.textContent = 'Adding...';
            const forced = await api('/api/targets', 'POST', {
                ip, mac: result.mac, hostname: result.hostname, force: true,
            });
            btn.disabled = false;
            btn.textContent = 'Add';
            if (forced && !forced._error && forced.ok) {
                ipInput.value = '';
                await refreshTargets();
                await refreshLog();
            } else {
                alert(forced?.error || 'Failed to add target');
            }
        }
        return;
    }

    btn.disabled = false;
    btn.textContent = 'Add';

    if (result && !result._error && result.ok) {
        ipInput.value = '';
        await refreshTargets();
        await refreshLog();
    } else {
        alert(result?.error || result?.detail || 'Failed to add target');
    }
});

// === Log ===

async function refreshLog() {
    const logs = await api('/api/log');
    if (!logs || logs._error) return;
    const list = document.getElementById('log-list');

    if (logs.length === 0) {
        list.innerHTML = '<p class="dim">No activity yet</p>';
        return;
    }

    list.innerHTML = logs.slice(0, 30).map(l => {
        const d = new Date(l.timestamp + 'Z');
        const time = d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', hour12: true });
        const who = l.hostname || l.target_mac || '';
        const label = who ? ` [${who}]` : '';
        return `<div class="log-item"><span class="log-time">${time}</span>${label} \u2014 ${l.action} (${l.source})</div>`;
    }).join('');
}

// === Init ===

async function init() {
    initTimePickers();
    await Promise.all([checkPiholeStatus(), refreshTargets(), refreshLog(), loadCachedDevices()]);
    setInterval(refreshTargets, 5000);
    setInterval(refreshLog, 15000);
    setInterval(loadCachedDevices, 30000);
}

init();
