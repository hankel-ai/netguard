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

function fmt12(time24) {
    if (!time24) return '';
    const [h, m] = time24.split(':').map(Number);
    const suffix = h >= 12 ? 'PM' : 'AM';
    const h12 = h % 12 || 12;
    return `${h12}:${String(m).padStart(2, '0')} ${suffix}`;
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
        matchesSearch(query, t.hostname, t.target_ip || t.ip, t.mac)
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
    const statusClass = blocked ? 'blocked' : 'unblocked';
    const statusText = blocked ? 'BLOCKED' : 'UNBLOCKED';
    const displayName = t.hostname || 'Unknown Device';
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
            scheduleSummary = `${t.schedules.length} rule(s), all disabled`;
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

    return `
    <div class="card target-card" data-id="${t.id}">
        <div class="target-header">
            <div class="target-info">
                <div class="target-name">${esc(displayName)}</div>
                <div class="target-details">${esc(ip)} &middot; ${esc(t.mac)}</div>
            </div>
            <div class="status-badge ${statusClass}">
                <span class="dot"></span> ${statusText}
            </div>
        </div>
        <div class="target-desc" data-action="edit-desc">
            ${desc ? esc(desc) : '<span class="dim">Add description...</span>'}
        </div>
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
            <button class="btn btn-delete btn-sm" data-action="delete" data-name="${esc(displayName)}">\u00d7</button>
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
    if (action === 'delete') {
        const name = btn.dataset.name || 'this target';
        if (!confirm(`Remove "${name}"? This will unblock it and delete all its schedules.`)) return;
        await api(`/api/targets/${id}`, 'DELETE');
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

function openScheduleModal(targetId, name) {
    _scheduleTargetId = targetId;
    document.getElementById('schedule-modal-title').textContent = `Schedule: ${name}`;
    document.getElementById('schedule-modal').hidden = false;
    refreshScheduleModal();
}

function closeScheduleModal() {
    document.getElementById('schedule-modal').hidden = true;
    _scheduleTargetId = null;
}

document.getElementById('btn-close-schedule').addEventListener('click', closeScheduleModal);

async function refreshScheduleModal() {
    if (!_scheduleTargetId) return;
    const rules = await api(`/api/targets/${_scheduleTargetId}/schedules`);
    if (!rules || rules._error) return;
    const list = document.getElementById('schedule-rules-list');

    if (rules.length === 0) {
        list.innerHTML = '<p class="dim">No rules yet. Add one below.</p>';
        return;
    }

    list.innerHTML = rules.map(r => `
        <div class="rule-item">
            <span class="rule-label ${r.enabled ? '' : 'disabled'}">
                ${DAY_LABELS[r.day_of_week] || r.day_of_week} ${fmt12(r.start_time)}\u2013${fmt12(r.end_time)}
            </span>
            <div class="rule-actions">
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
    if (btn.dataset.ruleAction === 'toggle') {
        await api(`/api/schedules/${ruleId}/toggle`, 'PATCH');
    } else if (btn.dataset.ruleAction === 'delete') {
        await api(`/api/schedules/${ruleId}`, 'DELETE');
    }
    await refreshScheduleModal();
    await refreshTargets();
});

document.getElementById('schedule-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!_scheduleTargetId) return;
    const day = document.getElementById('rule-day').value;
    const start = document.getElementById('rule-start').value;
    const end = document.getElementById('rule-end').value;
    if (!start || !end) return;
    await api(`/api/targets/${_scheduleTargetId}/schedules`, 'POST', {
        day_of_week: day, start_time: start, end_time: end,
    });
    document.getElementById('rule-start').value = '';
    document.getElementById('rule-end').value = '';
    await refreshScheduleModal();
    await refreshTargets();
});

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

    const devices = await api('/api/scan', 'POST');
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
        matchesSearch(query, d.hostname, d.ip, d.mac)
    );

    if (filtered.length === 0) {
        el.innerHTML = '<div class="card empty">No devices match your search.</div>';
        return;
    }

    el.innerHTML = filtered.map((d, _) => {
        const realIdx = _scanResults.indexOf(d);
        return `
        <div class="scan-device ${d.is_target ? 'already-added' : ''}">
            <div class="scan-device-info">
                <div class="scan-device-name">${d.hostname ? esc(d.hostname) : '<em>Unknown</em>'}</div>
                <div class="scan-device-details">${esc(d.ip)} &middot; ${esc(d.mac)}</div>
            </div>
            ${d.is_target
                ? '<span class="dim">Added</span>'
                : `<button class="btn btn-primary btn-sm" data-scan-idx="${realIdx}">Add</button>`
            }
        </div>`;
    }).join('');
}

// Event delegation for scan results
document.getElementById('scan-list').addEventListener('click', async (e) => {
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
    await Promise.all([refreshTargets(), refreshLog(), loadCachedDevices()]);
    setInterval(refreshTargets, 5000);
    setInterval(refreshLog, 15000);
}

init();
