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

// === Targets ===

async function refreshTargets() {
    const targets = await api('/api/targets');
    if (!targets || targets._error) return;
    const list = document.getElementById('targets-list');

    if (targets.length === 0) {
        list.innerHTML = '<div class="card empty">No targets configured. Scan your LAN or add one manually.</div>';
        return;
    }

    list.innerHTML = targets.map(renderTargetCard).join('');
}

function renderTargetCard(t) {
    const blocked = t.is_blocking;
    const statusClass = blocked ? 'blocked' : 'unblocked';
    const statusText = blocked ? 'BLOCKED' : 'UNBLOCKED';
    const displayName = t.hostname || 'Unknown Device';
    const ip = t.target_ip || t.ip || '\u2014';
    const hasOverride = t.override !== 'none';

    let scheduleSummary = '';
    if (t.schedules && t.schedules.length > 0) {
        const enabled = t.schedules.filter(s => s.enabled);
        if (enabled.length > 0) {
            scheduleSummary = enabled.map(s =>
                `${DAY_LABELS[s.day_of_week] || s.day_of_week} ${s.start_time}\u2013${s.end_time}`
            ).join(', ');
        } else {
            scheduleSummary = `${t.schedules.length} rule(s), all disabled`;
        }
    }

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
        ${hasOverride ? `<div class="override-badge">Override: ${t.override}</div>` : ''}
        <div class="target-schedule" data-action="schedule" data-name="${esc(displayName)}">
            ${scheduleSummary
                ? `<span class="schedule-icon">\u{1F551}</span> ${esc(scheduleSummary)}`
                : '<span class="schedule-icon">\u{1F551}</span> No schedule \u2014 tap to add'
            }
        </div>
        <div class="target-actions">
            <button class="btn btn-danger btn-sm" data-action="block">BLOCK</button>
            <button class="btn btn-success btn-sm" data-action="unblock">UNBLOCK</button>
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
                ${DAY_LABELS[r.day_of_week] || r.day_of_week} ${r.start_time}\u2013${r.end_time}
            </span>
            <div class="rule-actions">
                <button class="btn btn-sm btn-secondary" data-rule-action="toggle" data-rule-id="${r.id}">${r.enabled ? '\u2611' : '\u2610'}</button>
                <button class="btn btn-sm btn-danger" data-rule-action="delete" data-rule-id="${r.id}">\u2715</button>
            </div>
        </div>
    `).join('');
}

// Event delegation for schedule rules
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

// === LAN Scan Modal ===

let _scanResults = [];

async function openScanModal() {
    document.getElementById('scan-modal').hidden = false;
    document.getElementById('scan-results').innerHTML = '<p class="dim">Scanning network... this may take a moment.</p>';
    const devices = await api('/api/scan', 'POST');
    if (!devices || devices._error) {
        document.getElementById('scan-results').innerHTML = '<p class="dim">Scan failed. Try again.</p>';
        return;
    }
    _scanResults = devices;
    renderScanResults();
}

function renderScanResults() {
    const el = document.getElementById('scan-results');
    if (_scanResults.length === 0) {
        el.innerHTML = '<p class="dim">No devices found.</p>';
        return;
    }
    el.innerHTML = _scanResults.map((d, i) => `
        <div class="scan-device ${d.is_target ? 'already-added' : ''}">
            <div class="scan-device-info">
                <div class="scan-device-name">${d.hostname ? esc(d.hostname) : '<em>Unknown</em>'}</div>
                <div class="scan-device-details">${esc(d.ip)} &middot; ${esc(d.mac)}</div>
            </div>
            ${d.is_target
                ? '<span class="dim">Added</span>'
                : `<button class="btn btn-primary btn-sm" data-scan-idx="${i}">Add</button>`
            }
        </div>
    `).join('');
}

// Event delegation for scan results
document.getElementById('scan-results').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-scan-idx]');
    if (!btn) return;
    const idx = parseInt(btn.dataset.scanIdx);
    const d = _scanResults[idx];
    if (!d) return;

    btn.disabled = true;
    btn.textContent = 'Adding...';
    const result = await api('/api/targets', 'POST', {
        mac: d.mac,
        ip: d.ip || null,
        hostname: d.hostname || null,
    });
    if (result && !result._error && result.ok) {
        d.is_target = true;
        renderScanResults();
        await refreshTargets();
        await refreshLog();
    } else {
        btn.textContent = result?.error || 'Failed';
        btn.disabled = true;
    }
});

function closeScanModal() {
    document.getElementById('scan-modal').hidden = true;
}

// === Manual Add ===

document.getElementById('add-target-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const macInput = document.getElementById('add-mac');
    const hostInput = document.getElementById('add-hostname');
    const mac = macInput.value.trim();
    const hostname = hostInput.value.trim() || null;
    if (!mac) return;

    const btn = e.target.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Adding...';

    const result = await api('/api/targets', 'POST', { mac, hostname });
    btn.disabled = false;
    btn.textContent = 'Add';

    if (result && !result._error && result.ok) {
        macInput.value = '';
        hostInput.value = '';
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

    list.innerHTML = logs.slice(0, 20).map(l => {
        const d = new Date(l.timestamp + 'Z');
        const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const who = l.hostname || l.target_mac || '';
        const label = who ? ` [${who}]` : '';
        return `<div class="log-item"><span class="log-time">${time}</span>${label} \u2014 ${l.action} (${l.source})</div>`;
    }).join('');
}

// === Init ===

async function init() {
    await Promise.all([refreshTargets(), refreshLog()]);
    setInterval(refreshTargets, 5000);
    setInterval(refreshLog, 15000);
}

init();
