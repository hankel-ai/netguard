// NetGuard — multi-target frontend

async function api(path, method = 'GET', body = null) {
    const opts = { method, headers: {} };
    if (body) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    if (res.status === 401) { window.location.href = '/'; return null; }
    return res.json();
}

const DAY_LABELS = {
    weekday: 'Weekdays', weekend: 'Weekend',
    mon: 'Mon', tue: 'Tue', wed: 'Wed', thu: 'Thu', fri: 'Fri', sat: 'Sat', sun: 'Sun'
};

// === Targets ===

async function refreshTargets() {
    const targets = await api('/api/targets');
    if (!targets) return;
    const list = document.getElementById('targets-list');

    if (targets.length === 0) {
        list.innerHTML = '<div class="card empty">No targets configured. Scan your LAN or add one manually.</div>';
        return;
    }

    list.innerHTML = targets.map(t => renderTargetCard(t)).join('');
}

function renderTargetCard(t) {
    const blocked = t.is_blocking;
    const statusClass = blocked ? 'blocked' : 'unblocked';
    const statusText = blocked ? 'BLOCKED' : 'UNBLOCKED';
    const displayName = t.hostname || 'Unknown Device';
    const ip = t.target_ip || t.ip || '—';
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
    <div class="card target-card">
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

        <div class="target-schedule" onclick="openScheduleModal(${t.id}, '${esc(displayName)}')">
            ${scheduleSummary
                ? `<span class="schedule-icon">&#128337;</span> ${esc(scheduleSummary)}`
                : '<span class="schedule-icon">&#128337;</span> No schedule &mdash; tap to add'
            }
        </div>

        <div class="target-actions">
            <button class="btn btn-danger btn-sm" onclick="targetAction(${t.id}, 'block')">BLOCK</button>
            <button class="btn btn-success btn-sm" onclick="targetAction(${t.id}, 'unblock')">UNBLOCK</button>
            ${hasOverride ? `<button class="btn btn-secondary btn-sm" onclick="targetAction(${t.id}, 'clear-override')">CLEAR</button>` : ''}
            <button class="btn btn-delete btn-sm" onclick="deleteTarget(${t.id}, '${esc(displayName)}')">&times;</button>
        </div>
    </div>`;
}

function esc(s) {
    if (!s) return '';
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

async function targetAction(id, action) {
    await api(`/api/targets/${id}/${action}`, 'POST');
    await refreshTargets();
    await refreshLog();
}

async function deleteTarget(id, name) {
    if (!confirm(`Remove target "${name}"? This will unblock it and delete all its schedules.`)) return;
    await api(`/api/targets/${id}`, 'DELETE');
    await refreshTargets();
    await refreshLog();
}

// === Schedule Modal ===

let _scheduleTargetId = null;

async function openScheduleModal(targetId, name) {
    _scheduleTargetId = targetId;
    document.getElementById('schedule-modal-title').textContent = `Schedule: ${name}`;
    document.getElementById('schedule-modal').hidden = false;
    await refreshScheduleModal();
}

function closeScheduleModal() {
    document.getElementById('schedule-modal').hidden = true;
    _scheduleTargetId = null;
}

async function refreshScheduleModal() {
    if (!_scheduleTargetId) return;
    const rules = await api(`/api/targets/${_scheduleTargetId}/schedules`);
    if (!rules) return;
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
                <button class="btn btn-sm btn-secondary" onclick="toggleRule(${r.id})">${r.enabled ? '\u2611' : '\u2610'}</button>
                <button class="btn btn-sm btn-danger" onclick="deleteRule(${r.id})">\u2715</button>
            </div>
        </div>
    `).join('');
}

async function toggleRule(ruleId) {
    await api(`/api/schedules/${ruleId}/toggle`, 'PATCH');
    await refreshScheduleModal();
    await refreshTargets();
}

async function deleteRule(ruleId) {
    await api(`/api/schedules/${ruleId}`, 'DELETE');
    await refreshScheduleModal();
    await refreshTargets();
}

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

async function openScanModal() {
    document.getElementById('scan-modal').hidden = false;
    document.getElementById('scan-results').innerHTML = '<p class="dim">Scanning network...</p>';
    const devices = await api('/api/scan', 'POST');
    if (!devices) return;

    if (devices.length === 0) {
        document.getElementById('scan-results').innerHTML = '<p class="dim">No devices found.</p>';
        return;
    }

    document.getElementById('scan-results').innerHTML = devices.map(d => `
        <div class="scan-device ${d.is_target ? 'already-added' : ''}">
            <div class="scan-device-info">
                <div class="scan-device-name">${esc(d.hostname) || '<em>Unknown</em>'}</div>
                <div class="scan-device-details">${esc(d.ip)} &middot; ${esc(d.mac)}</div>
            </div>
            ${d.is_target
                ? '<span class="dim">Added</span>'
                : `<button class="btn btn-primary btn-sm" onclick="addFromScan('${esc(d.mac)}', '${esc(d.ip)}', '${esc(d.hostname || '')}')">Add</button>`
            }
        </div>
    `).join('');
}

function closeScanModal() {
    document.getElementById('scan-modal').hidden = true;
}

async function addFromScan(mac, ip, hostname) {
    await api('/api/targets', 'POST', { mac, ip: ip || null, hostname: hostname || null });
    closeScanModal();
    await refreshTargets();
    await refreshLog();
}

// === Manual Add ===

document.getElementById('add-target-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const mac = document.getElementById('add-mac').value.trim();
    const hostname = document.getElementById('add-hostname').value.trim() || null;
    const result = await api('/api/targets', 'POST', { mac, hostname });
    if (result && result.ok) {
        document.getElementById('add-mac').value = '';
        document.getElementById('add-hostname').value = '';
        await refreshTargets();
        await refreshLog();
    } else if (result) {
        alert(result.error || 'Failed to add target');
    }
});

// === Log ===

async function refreshLog() {
    const logs = await api('/api/log');
    if (!logs) return;
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
        return `<div class="log-item"><span class="log-time">${time}</span>${label} — ${l.action} (${l.source})</div>`;
    }).join('');
}

// === Init ===

async function init() {
    await Promise.all([refreshTargets(), refreshLog()]);
    setInterval(refreshTargets, 5000);
    setInterval(refreshLog, 15000);
}

init();
