// NetGuard frontend

async function api(path, method = 'GET', body = null) {
    const opts = { method, headers: {} };
    if (body) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    if (res.status === 401) {
        window.location.href = '/';
        return null;
    }
    return res.json();
}

// --- Status ---

async function refreshStatus() {
    const data = await api('/api/status');
    if (!data) return;

    const indicator = document.getElementById('status-indicator');
    const text = document.getElementById('status-text');
    const badge = document.getElementById('override-badge');
    const clearBtn = document.getElementById('btn-clear');
    const info = document.getElementById('target-info');

    if (data.is_blocking) {
        indicator.className = 'status-indicator blocked';
        text.textContent = 'BLOCKED';
    } else {
        indicator.className = 'status-indicator unblocked';
        text.textContent = 'UNBLOCKED';
    }

    if (data.override !== 'none') {
        badge.hidden = false;
        clearBtn.hidden = false;
    } else {
        badge.hidden = true;
        clearBtn.hidden = true;
    }

    info.textContent = `Target: ${data.target_mac} (${data.target_ip || 'IP unknown'}) · Gateway: ${data.gateway_ip}`;
}

// --- Actions ---

async function doAction(action) {
    await api(`/api/${action}`, 'POST');
    await refreshStatus();
    await refreshLog();
}

// --- Schedules ---

async function refreshSchedules() {
    const rules = await api('/api/schedules');
    if (!rules) return;
    const list = document.getElementById('schedule-list');

    if (rules.length === 0) {
        list.innerHTML = '<p style="color:var(--text-dim);font-size:0.9rem;">No schedule rules</p>';
        return;
    }

    list.innerHTML = rules.map(r => `
        <div class="rule-item">
            <span class="rule-label ${r.enabled ? '' : 'disabled'}">
                ${dayLabel(r.day_of_week)} ${r.start_time}–${r.end_time}
            </span>
            <div class="rule-actions">
                <button class="btn btn-sm btn-secondary" onclick="toggleRule(${r.id})">${r.enabled ? '☑' : '☐'}</button>
                <button class="btn btn-sm btn-danger" onclick="deleteRule(${r.id})">✕</button>
            </div>
        </div>
    `).join('');
}

function dayLabel(d) {
    const map = {
        weekday: 'Weekdays', weekend: 'Weekend',
        mon: 'Mon', tue: 'Tue', wed: 'Wed', thu: 'Thu', fri: 'Fri', sat: 'Sat', sun: 'Sun'
    };
    return map[d] || d;
}

async function toggleRule(id) {
    await api(`/api/schedules/${id}/toggle`, 'PATCH');
    await refreshSchedules();
}

async function deleteRule(id) {
    await api(`/api/schedules/${id}`, 'DELETE');
    await refreshSchedules();
}

document.getElementById('add-rule-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const day = document.getElementById('rule-day').value;
    const start = document.getElementById('rule-start').value;
    const end = document.getElementById('rule-end').value;
    if (!start || !end) return;
    await api('/api/schedules', 'POST', {
        day_of_week: day,
        start_time: start,
        end_time: end,
    });
    document.getElementById('rule-start').value = '';
    document.getElementById('rule-end').value = '';
    await refreshSchedules();
});

// --- Log ---

async function refreshLog() {
    const logs = await api('/api/log');
    if (!logs) return;
    const list = document.getElementById('log-list');

    if (logs.length === 0) {
        list.innerHTML = '<p style="color:var(--text-dim);font-size:0.9rem;">No activity yet</p>';
        return;
    }

    list.innerHTML = logs.slice(0, 20).map(l => {
        const d = new Date(l.timestamp + 'Z');
        const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        return `<div class="log-item"><span class="log-time">${time}</span> — ${l.action} (${l.source})</div>`;
    }).join('');
}

// --- Init ---

async function init() {
    await Promise.all([refreshStatus(), refreshSchedules(), refreshLog()]);
    // Poll status every 5s
    setInterval(refreshStatus, 5000);
    // Refresh log less frequently
    setInterval(refreshLog, 15000);
}

init();
