const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (x, d = 2) => (x === null || x === undefined ? "n/a" : Number(x).toFixed(d));
const pct = (x, d = 0) => (x === null || x === undefined ? "n/a" : (x * 100).toFixed(d) + "%");
const COLORS = {
    Benign: "#10b981", "DoS/DDoS": "#ef4444", Recon: "#f97316", "Brute force": "#8b5cf6",
    "Web attack": "#2563eb", Botnet: "#ec4899", Infiltration: "#a855f7", Exploit: "#64748b", Other: "#71717a"
};
const FAMILIES = ["Benign", "DoS/DDoS", "Recon", "Brute force", "Web attack", "Botnet", "Infiltration", "Exploit", "Other"];

// ---------- Authentication & RBAC Session State ----------
let currentUser = null;
window.currentUser = null;

async function checkAuth() {
    try {
        const res = await fetch("/api/auth/me");
        if (!res.ok) {
            window.location.href = "/login.html";
            return false;
        }
        const data = await res.json();
        currentUser = data.user;
        window.currentUser = data.user;
        renderUserBadge();
        applyRbacUI();
        return true;
    } catch (e) {
        window.location.href = "/login.html";
        return false;
    }
}

function renderUserBadge() {
    if (!currentUser) return;
    if ($("userName")) $("userName").textContent = currentUser.full_name || currentUser.username;
    const badge = $("userRoleBadge");
    if (badge) {
        badge.textContent = (currentUser.role || "analyst").toUpperCase();
        badge.className = "user-role-label " + currentUser.role;
    }
    const avatar = $("userAvatar");
    if (avatar) {
        const name = (currentUser.full_name || currentUser.username || "Op").trim();
        const parts = name.split(/\s+/);
        const initials = parts.length > 1 ? (parts[0][0] + parts[parts.length - 1][0]) : name.slice(0, 2);
        avatar.textContent = initials.toUpperCase();
    }
}

function applyRbacUI() {
    if (!currentUser) return;
    const isAdmin = currentUser.role === "admin";
    if ($("tabIngestion")) $("tabIngestion").style.display = isAdmin ? "" : "none";
    if ($("tabUsers")) $("tabUsers").style.display = isAdmin ? "" : "none";
}

async function api(path, body) {
    const opts = body !== undefined
        ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
        : undefined;
    const res = await fetch(path, opts);
    if (res.status === 401) {
        window.location.href = "/login.html";
        throw new Error("401 Unauthorized");
    }
    if (!res.ok) throw new Error(res.status + " " + path);
    return res.json();
}

// ---------- Tab Routing (Multi-View) ----------
function switchTab(tabId) {
    document.querySelectorAll(".tab-item").forEach((t) => {
        t.classList.toggle("active", t.dataset.tab === tabId);
    });
    document.querySelectorAll(".page-view").forEach((v) => {
        v.classList.add("hidden");
    });
    const target = $("view-" + tabId);
    if (target) target.classList.remove("hidden");
    window.location.hash = "#/" + tabId;

    const titles = {
        live: "Live Threat Feed",
        incidents: "Incidents & Triage",
        models: "Model Health & XAI",
        ingestion: "Data Ingestion Pipeline",
        users: "Access Control & RBAC"
    };
    if ($("currentViewName")) $("currentViewName").textContent = titles[tabId] || tabId;

    if (tabId === "users" && currentUser?.role === "admin") {
        loadUsers();
    }
}

function initRouting() {
    const hash = (window.location.hash || "").replace("#/", "");
    const valid = ["live", "incidents", "models", "ingestion", "users"];
    const initial = valid.includes(hash) ? hash : "live";
    switchTab(initial);

    // Global listener for tab switches across sidebar
    document.addEventListener("click", (e) => {
        const btn = e.target.closest(".tab-item");
        if (btn && btn.dataset.tab) {
            switchTab(btn.dataset.tab);
        }
    });

    window.addEventListener("hashchange", () => {
        const h = (window.location.hash || "").replace("#/", "");
        if (valid.includes(h)) switchTab(h);
    });
}

// ---------- User Management (Admin Only) ----------
async function loadUsers() {
    if (!currentUser || currentUser.role !== "admin") return;
    try {
        const res = await api("/api/auth/users");
        const tbody = $("usersTableBody");
        if (!tbody || !res.users) return;
        tbody.innerHTML = res.users.map((u) => `
            <tr>
                <td><span class="mono" style="color:var(--text-muted);">#${esc(u.id)}</span></td>
                <td><strong style="font-family:var(--font-mono);">${esc(u.username)}</strong></td>
                <td>${esc(u.full_name)}</td>
                <td><span class="user-role-label ${esc(u.role)}">${esc(u.role)}</span></td>
                <td><span class="mono" style="color:var(--text-secondary); font-size:11px;">${u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}</span></td>
                <td>${u.id !== currentUser.id && u.is_active ?
                    `<button class="btn-outline-danger" onclick="deactivateUser(${u.id})">Deactivate</button>` :
                    '<span style="color:var(--text-muted);">—</span>'}</td>
            </tr>
        `).join("");
    } catch (e) {
        console.warn("loadUsers failed:", e);
    }
}

window.deactivateUser = async (id) => {
    if (!confirm("Deactivate this user account?")) return;
    try {
        const res = await fetch("/api/auth/users/" + id, { method: "DELETE" });
        if (res.ok) {
            loadUsers();
        } else {
            const d = await res.json();
            alert(d.detail || "Failed to deactivate user");
        }
    } catch (e) {
        alert("Failed to deactivate user");
    }
};

function initUserManagement() {
    const form = $("createUserForm");
    if (form) {
        form.onsubmit = async (e) => {
            e.preventDefault();
            const msg = $("createUserMsg");
            const username = $("newUsername").value.trim();
            const password = $("newPassword").value;
            const full_name = $("newFullName").value.trim();
            const role = $("newRole").value;
            msg.textContent = "Provisioning user account…";
            try {
                const res = await fetch("/api/auth/users", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, password, full_name, role })
                });
                const d = await res.json();
                if (!res.ok) {
                    msg.textContent = d.detail || "Error creating user";
                    msg.style.color = "var(--status-critical)";
                } else {
                    msg.textContent = `User '${username}' provisioned successfully.`;
                    msg.style.color = "var(--status-safe)";
                    form.reset();
                    loadUsers();
                }
            } catch (err) {
                msg.textContent = "Failed to create user";
                msg.style.color = "var(--status-critical)";
            }
        };
    }
}

// ---------- Theming & Real-time WebSocket ----------
function getPreferredTheme() {
    const saved = localStorage.getItem("pids-theme");
    if (saved === "dark" || saved === "light") return saved;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("pids-theme", theme);
    const isDark = theme === "dark";
    if ($("themeIcon")) {
        $("themeIcon").innerHTML = isDark
            ? '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" style="display:inline-block; vertical-align:middle; margin-right:4px;"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>'
            : '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" style="display:inline-block; vertical-align:middle; margin-right:4px;"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
    }
    if ($("themeLabel")) $("themeLabel").textContent = isDark ? "Light Mode" : "Dark Mode";

    const textColor = isDark ? "#94a3b8" : "#475569";
    const gridColor = isDark ? "rgba(255, 255, 255, 0.06)" : "rgba(0, 0, 0, 0.06)";

    if (typeof Chart !== "undefined") {
        Chart.defaults.color = textColor;
        Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
        [trafficChart, forecastChart, portsChart, histChart, calibChart].forEach((c) => {
            if (c && c.options && c.options.scales) {
                Object.values(c.options.scales).forEach((s) => {
                    if (s.grid) s.grid.color = gridColor;
                    if (s.ticks) s.ticks.color = textColor;
                });
                c.update("none");
            }
        });
    }
}

function initTheme() {
    const current = getPreferredTheme();
    applyTheme(current);
    const btn = $("themeToggle");
    if (btn) {
        btn.onclick = () => {
            const cur = document.documentElement.getAttribute("data-theme") || "dark";
            applyTheme(cur === "dark" ? "light" : "dark");
        };
    }
    if (window.matchMedia) {
        window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
            if (!localStorage.getItem("pids-theme")) {
                applyTheme(e.matches ? "dark" : "light");
            }
        });
    }
}

let ws = null;
let wsBackoff = 1000;
let wsConnected = false;

function setWsStatus(online) {
    const el = $("wsStatus");
    if (!el) return;
    if (online) {
        el.textContent = "Stream: Live";
        el.className = "badge-tag online";
        el.title = "WebSocket Connected";
    } else {
        el.textContent = "Stream: Polling";
        el.className = "badge-tag offline";
        el.title = "WebSocket Disconnected";
    }
}

function initWebSocket() {
    const wsProto = location.protocol === "https:" ? "wss://" : "ws://";
    const wsUrl = wsProto + location.host + "/ws";
    try {
        ws = new WebSocket(wsUrl);
    } catch (e) {
        setWsStatus(false);
        return;
    }

    ws.onopen = () => {
        wsConnected = true;
        wsBackoff = 1000;
        setWsStatus(true);
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === "tick" || msg.type === "connected") {
                refresh();
                if (typeof window.loadIncidents === "function") {
                    window.loadIncidents();
                }
            }
        } catch (e) { /* ignore parse error */ }
    };

    ws.onclose = () => {
        wsConnected = false;
        setWsStatus(false);
        setTimeout(initWebSocket, Math.min(wsBackoff *= 1.5, 10000));
    };

    ws.onerror = () => {
        wsConnected = false;
        setWsStatus(false);
    };
}

// ---------- Charts ----------
let trafficChart, familyChart, forecastChart, portsChart, histChart, calibChart;
let chartsOk = false;

function initCharts() {
    const isDark = document.documentElement.getAttribute("data-theme") !== "light";
    const textColor = isDark ? "#94a3b8" : "#475569";
    const gridColor = isDark ? "rgba(255, 255, 255, 0.06)" : "rgba(0, 0, 0, 0.06)";
    if (typeof Chart !== "undefined") {
        Chart.defaults.color = textColor;
        Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
    }
    const base = {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        scales: {
            x: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } },
            y: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } }
        }
    };

    trafficChart = new Chart($("trafficChart"), {
        type: "line", data: { labels: [], datasets: [] },
        options: {
            ...base, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } },
            elements: { line: { tension: 0.1, borderWidth: 1.5 } },
            plugins: { legend: { position: "bottom", labels: { boxWidth: 8, font: { size: 10.5 } } } }
        }
    });

    familyChart = new Chart($("familyChart"), {
        type: "doughnut",
        data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
        options: {
            ...base,
            plugins: { legend: { position: "bottom", labels: { boxWidth: 8, font: { size: 10.5 } } } },
            cutout: "70%"
        }
    });

    forecastChart = new Chart($("forecastChart"), {
        type: "line", data: { labels: [], datasets: [] },
        options: {
            ...base, spanGaps: false,
            scales: { y: { min: 0, max: 1, ticks: { callback: (v) => Math.round(v * 100) + "%" } } },
            elements: { line: { tension: 0.1, borderWidth: 1.5 } },
            plugins: { legend: { position: "bottom", labels: { boxWidth: 8, font: { size: 10.5 } } } }
        }
    });

    portsChart = new Chart($("portsChart"), {
        type: "bar",
        data: { labels: [], datasets: [{ label: "Flows", data: [], backgroundColor: "#f97316", borderRadius: 2 }] },
        options: { ...base, plugins: { legend: { display: false } } }
    });

    histChart = new Chart($("histChart"), {
        type: "bar",
        data: { labels: [], datasets: [{ label: "Flows", data: [], backgroundColor: "#2563eb", borderRadius: 2 }] },
        options: { ...base, plugins: { legend: { display: false } } }
    });

    chartsOk = true;
}

function updateCharts(s) {
    trafficChart.data.labels = s.traffic.labels;
    trafficChart.data.datasets = Object.entries(s.traffic.series).map(([fam, data]) => ({
        label: fam, data, fill: true, pointRadius: 0, borderWidth: 1.2,
        borderColor: COLORS[fam] || "#888", backgroundColor: (COLORS[fam] || "#888") + "26"
    }));
    trafficChart.update();

    const fams = Object.keys(s.families);
    familyChart.data.labels = fams;
    familyChart.data.datasets[0].data = fams.map((f) => s.families[f]);
    familyChart.data.datasets[0].backgroundColor = fams.map((f) => COLORS[f] || "#888");
    familyChart.update();

    if (s.top_ports) {
        portsChart.data.labels = s.top_ports.map((p) => p[0]);
        portsChart.data.datasets[0].data = s.top_ports.map((p) => p[1]);
        portsChart.update();
    }
    if (s.hist) {
        $("histTitle").textContent = s.hist.ae ? "Anomaly Score (Threshold: 1.0)" : "Attack Probability Score";
        histChart.data.labels = s.hist.edges.map((e) => e.toFixed(2));
        histChart.data.datasets[0].data = s.hist.counts;
        histChart.update();
    }
}

// ---------- Rendering ----------
function kpiHtml(items) {
    return items.map(([l, v]) => {
        const isCrit = l === "Critical (open)" && Number(v) > 0;
        return `
        <div class="kpi-card ${isCrit ? 'crit-alert' : ''}">
            <div class="kpi-header">
                <span class="kpi-label">${esc(l)}</span>
                ${isCrit ? '<span class="kpi-badge-alert">ACTIVE</span>' : ''}
            </div>
            <div class="kpi-value">${esc(v)}</div>
        </div>`;
    }).join("");
}

function render(s) {
    if ($("status")) {
        $("status").textContent = s.live ? "Scoring: Active" : "Scoring: Paused";
        $("status").className = "badge-tag" + (s.live ? " online" : "");
    }
    if ($("meta")) {
        $("meta").textContent = `${s.model}${s.autoencoder ? " + AE" : ""} · Buffer: ${(s.queued ?? 0).toLocaleString()} · Agreement: ${pct(s.selftest, 1)}`;
    }
    if ($("healthWarn")) {
        $("healthWarn").textContent = s.held_out ? "" :
            "Replay flows may include training samples; metrics are for validation sanity checks.";
    }
    const err = $("error");
    if (err) {
        err.textContent = s.error || "";
        err.classList.toggle("hidden", !s.error);
    }
    if ($("waiting")) {
        $("waiting").classList.toggle("hidden", s.has_data);
    }

    if (!s.has_data) return;

    // KPIs
    const kpiItems = [
        ["Attack rate (overall)", pct(s.kpi.attack_rate, 1)],
        ["Critical (open)", s.kpi.open_critical],
        ["Escalated", s.kpi.escalated],
        ["Avg confidence", pct(s.kpi.avg_conf, 1)],
    ];
    if (s.kpi.anomalies !== null && s.kpi.anomalies !== undefined) {
        kpiItems.push(["Anomalies (score > 1)", s.kpi.anomalies]);
    }
    if ($("kpis")) $("kpis").innerHTML = kpiHtml(kpiItems);

    // Live Feed Table
    if ($("feed")) {
        $("feed").innerHTML = "<thead><tr><th>Event ID</th><th>Timestamp</th><th>Verdict</th><th>Signature / Attack</th><th>Confidence</th><th>Source → Destination Flow</th></tr></thead><tbody>" +
            s.feed.map((r) => `<tr>
                <td><span class="mono" style="color:var(--text-muted);">#${esc(r.event_id)}</span></td>
                <td><span class="mono" style="color:var(--text-secondary);">${esc(r.capture_time)}</span></td>
                <td><span class="status-pill ${esc(r.verdict)}">${esc(r.verdict)}</span></td>
                <td><span style="font-weight:600;">${esc(r.predicted)}</span></td>
                <td><span class="mono">${num(r.confidence)}</span></td>
                <td><span class="mono">${esc(r.src_ip)} <span style="color:var(--text-muted); font-size:11px;">→</span> ${esc(r.dst_ip)}:${esc(r.dst_port)}</span></td>
            </tr>`).join("") + "</tbody>";
    }

    if (chartsOk) updateCharts(s);

    // Top Source IPs
    if ($("topIps")) {
        $("topIps").innerHTML = s.top_ips.map(([ip, n]) =>
            `<li><span class="mono" style="font-weight:600;">${esc(ip)}</span><span class="mono" style="color:var(--text-secondary); font-size:11px;">${n.toLocaleString()} flows</span></li>`).join("");
    }

    renderForecast(s.forecast);

    // Alert Queue Table
    if ($("queue")) {
        const isViewer = currentUser && currentUser.role === "viewer";
        const triageDisabled = isViewer ? 'disabled title="Analyst permission required"' : '';
        $("queue").innerHTML = "<thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Predicted Attack</th><th>Conf.</th><th>Attack Score</th><th>Anomaly</th><th>Flow Routing</th><th>Triage Actions</th></tr></thead><tbody>" +
            s.queue.map((r) => `<tr data-row="${esc(r.event_id)}" title="${esc(r.top3)}" style="cursor:pointer">
          <td><span class="mono" style="color:var(--text-muted);">#${esc(r.event_id)}</span></td>
          <td><span class="sev-${esc(r.severity)}" style="font-size:11.5px; text-transform:uppercase;">${esc(r.severity)}</span></td>
          <td><span class="badge-tag">${esc(r.status)}</span></td>
          <td><span style="font-weight:600;">${esc(r.predicted)}</span></td>
          <td><span class="mono">${num(r.confidence)}</span></td>
          <td><span class="mono">${num(r.attack_score)}</span></td>
          <td><span class="mono">${num(r.anomaly_score)}</span></td>
          <td><span class="mono">${esc(r.src_ip)} <span style="color:var(--text-muted); font-size:11px;">→</span> ${esc(r.dst_ip)}:${esc(r.dst_port)}</span></td>
          <td>
              <div class="btn-action-group">
                  <button class="btn-table-action" data-id="${esc(r.event_id)}" data-status="Acknowledged" ${triageDisabled}>Ack</button>
                  <button class="btn-table-action" data-id="${esc(r.event_id)}" data-status="False positive" ${triageDisabled}>FP</button>
                  <button class="btn-table-action danger" data-id="${esc(r.event_id)}" data-status="Escalated" ${triageDisabled}>Escalate</button>
              </div>
          </td></tr>`).join("") + "</tbody>";
    }
}

function renderForecast(fc) {
    if (!fc || !fc.ready) {
        if ($("fcNote")) $("fcNote").textContent = `Collecting window history (${fc ? fc.buckets : 0}/8 buckets)`;
        if ($("fcKpis")) $("fcKpis").innerHTML = "";
        if ($("fcFamily")) $("fcFamily").textContent = "";
        const w = $("warning");
        if (w) w.classList.add("hidden");
        return;
    }
    if ($("fcNote")) {
        $("fcNote").textContent = `Risk Level: ${fc.level} (Trend: ${fc.trend})` +
            (fc.skill !== null ? ` · Skill vs Naïve: ${pct(fc.skill, 0)}` : "");
    }

    const w = $("warning");
    if (w) {
        if (fc.level === "High" || fc.trend === "Rising") {
            w.textContent = `Forecast Alert: Attack share is ${fc.level.toLowerCase()} and ${fc.trend.toLowerCase()}. Expected share next 60s: ${pct(fc.next, 1)}.`;
            w.classList.remove("hidden");
        } else {
            w.classList.add("hidden");
        }
    }

    if ($("fcKpis")) {
        $("fcKpis").innerHTML = kpiHtml([
            ["Current share (~30 s)", pct(fc.now, 1)],
            ["Next 30 s forecast", pct(fc.next30, 1)],
            ["Next 60 s avg", pct(fc.next, 1)],
            ["Risk level", fc.level],
        ]);
    }

    if (chartsOk) {
        forecastChart.data.labels = fc.labels;
        forecastChart.data.datasets = [
            {
                label: "Observed attack share",
                data: fc.observed.concat(Array(fc.forecast.length).fill(null)),
                borderColor: "#2563eb", backgroundColor: "rgba(37, 99, 235, 0.1)",
                fill: true, tension: 0.1, borderWidth: 1.5
            },
            {
                label: "Holt forecast",
                data: Array(fc.observed.length - 1).fill(null).concat([fc.observed[fc.observed.length - 1]]).concat(fc.forecast),
                borderColor: "#ef4444", backgroundColor: "rgba(239, 68, 68, 0.1)",
                borderDash: [4, 4], fill: true, tension: 0.1, borderWidth: 1.5
            }
        ];
        forecastChart.update();
    }

    if ($("fcFamily")) {
        $("fcFamily").textContent = fc.top_family
            ? `Dominant threat family: ${fc.top_family} (${pct(fc.top_family_share, 0)} share)`
            : "Next threat family: None in recent window.";
    }
}

// ---------- Polling ----------
let busy = false, synced = false;

function syncBoxes() {
    if ($("watchBox")) $("watchBox").classList.toggle("hidden", $("source").value !== "watch");
    if ($("uploadBox")) $("uploadBox").classList.toggle("hidden", $("source").value !== "upload");
}

async function refresh() {
    if (busy || document.hidden) return;
    busy = true;
    try {
        const sev = [...document.querySelectorAll(".sev:checked")].map((c) => c.value).join(",");
        const fams = [...document.querySelectorAll(".fam:checked")].map((c) => c.value).join(",") || "__none__";
        const s = await api(`/api/state?min_conf=${$("minConf").value}&sev=${encodeURIComponent(sev)}&fams=${encodeURIComponent(fams)}`);
        if (!synced) {
            $("live").checked = s.live;
            if ($("rate")) $("rate").value = s.rate;
            if ($("source")) $("source").value = s.source;
            if ($("watchPath")) $("watchPath").value = s.watch_path;
            syncBoxes();
            synced = true;
        }
        render(s);
    } catch (e) {
        if (e.message !== "401 Unauthorized" && $("error")) {
            $("error").textContent = "Service unreachable: " + e.message;
            $("error").classList.remove("hidden");
        }
    } finally { busy = false; }
}

// ---------- Controls ----------
if ($("live")) $("live").onchange = () => api("/api/control", { live: $("live").checked }).then(refresh);
if ($("rate")) $("rate").onchange = () => api("/api/control", { rate: parseInt($("rate").value, 10) || 20 });
if ($("source")) $("source").onchange = () => {
    syncBoxes();
    api("/api/control", { source: $("source").value }).then(refresh);
};
if ($("watchPath")) $("watchPath").onchange = () => api("/api/control", { watch_path: $("watchPath").value })
    .then((r) => { if (!r.ok) alert(r.error); });
if ($("jump")) $("jump").onclick = () => api("/api/jump", { day: $("day").value })
    .then((r) => { if (!r.ok) alert(r.error); });
if ($("clear")) $("clear").onclick = () => api("/api/clear", {}).then(refresh);

let confTimer = null;
if ($("minConf")) {
    $("minConf").oninput = () => {
        $("minConfVal").textContent = Number($("minConf").value).toFixed(2);
        clearTimeout(confTimer);
        confTimer = setTimeout(refresh, 200);
    };
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
document.querySelectorAll(".sev").forEach((c) => (c.onchange = refresh));

if ($("famBox")) {
    $("famBox").innerHTML = FAMILIES.map((f) =>
        `<label><input type="checkbox" class="fam" value="${esc(f)}" checked> ${esc(f)}</label>`).join("");
    $("famBox").addEventListener("change", refresh);
}

if ($("ff")) {
    $("ff").onclick = async () => {
        $("ff").disabled = true;
        try {
            const r = await api("/api/fastforward", { ticks: 60 });
            if (!r.ok) alert(r.error);
        } catch (e) { alert("Fast-forward failed: " + e.message); }
        finally { $("ff").disabled = false; refresh(); }
    };
}

// ---------- Upload ----------
if ($("uploadFile")) {
    $("uploadFile").onchange = async () => {
        const f = $("uploadFile").files[0];
        if (!f) return;
        $("uploadMsg").textContent = "Processing packet capture…";
        const fd = new FormData();
        fd.append("file", f);
        try {
            const res = await fetch("/api/upload", { method: "POST", body: fd });
            const r = await res.json();
            $("uploadMsg").textContent = r.ok ? `Queued ${r.queued.toLocaleString()} flows` : (r.error || "Upload failed");
        } catch (e) { $("uploadMsg").textContent = "Upload failed: " + e.message; }
        refresh();
    };
}

// ---------- Alert Investigation Drawer ----------
async function openDrawer(id) {
    let r;
    try { r = await api("/api/alert/" + id); } catch (e) { return; }
    if (!r.found) return;
    const top3 = String(r.top3 || "").split(" | ").map((t) => `<li>${esc(t)}</li>`).join("");
    const isViewer = currentUser && currentUser.role === "viewer";
    const triageDisabled = isViewer ? 'disabled title="Analyst permission required"' : '';

    $("drawerBody").innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; border-bottom:1px solid var(--border-base); padding-bottom:10px;">
        <span class="mono" style="font-size:14px; font-weight:700;">ALERT #${esc(r.event_id)}</span>
        <span class="status-pill ${esc(r.verdict)}">${esc(r.verdict)}</span>
    </div>
    <div style="margin-bottom:14px; display:flex; align-items:center; justify-content:space-between;">
        <span class="sev-${esc(r.severity)}" style="font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.04em;">SEVERITY: ${esc(r.severity)}</span>
        <span class="mono" style="font-size:11px; color:var(--text-muted);">${esc(r.capture_time)}</span>
    </div>
    <dl class="drawer-dl">
      <dt>Predicted Attack</dt><dd><strong>${esc(r.predicted)}</strong> <span style="color:var(--text-muted);">(${esc(r.family)})</span></dd>
      <dt>Model Confidence</dt><dd>${pct(r.confidence, 1)}</dd>
      <dt>Attack Score</dt><dd>${num(r.attack_score)}</dd>
      <dt>Anomaly Score</dt><dd>${num(r.anomaly_score)}</dd>
      <dt>Uncertainty</dt><dd>${num(r.uncertainty)}</dd>
      <dt>Flow Routing</dt><dd style="font-size:11px;">${esc(r.src_ip)} → ${esc(r.dst_ip)}:${esc(r.dst_port)}</dd>
      <dt>Triage Status</dt><dd><span class="badge-tag">${esc(r.status)}</span></dd>
      <dt>Ground Truth</dt><dd>${esc(r.actual)} <span style="color:var(--text-muted); font-size:10px;">(Replay)</span></dd>
    </dl>
    <div style="margin-top:18px; font-size:11px; font-weight:600; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em;">Top 3 Class Attributions</div>
    <ul style="font-family:var(--font-mono); font-size:11.5px; line-height:1.8; color:var(--text-primary); padding-left:16px; margin:8px 0 18px;">${top3}</ul>
    <div style="display:flex; gap:6px; margin-top:20px;">
        <button class="btn-table-action" data-id="${esc(r.event_id)}" data-status="Acknowledged" ${triageDisabled}>Acknowledge</button>
        <button class="btn-table-action" data-id="${esc(r.event_id)}" data-status="False positive" ${triageDisabled}>False Positive</button>
        <button class="btn-table-action danger" data-id="${esc(r.event_id)}" data-status="Escalated" ${triageDisabled}>Escalate</button>
    </div>`;
    $("drawer").classList.remove("hidden");
}

if ($("drawerClose")) $("drawerClose").onclick = () => $("drawer").classList.add("hidden");
if ($("drawer")) {
    $("drawer").addEventListener("click", (e) => {
        const b = e.target.closest("button[data-id]");
        if (b && !b.disabled) {
            api("/api/status", { event_id: Number(b.dataset.id), status: b.dataset.status })
                .then(() => { refresh(); openDrawer(Number(b.dataset.id)); });
        }
    });
}
if ($("queue")) {
    $("queue").addEventListener("click", (e) => {
        const b = e.target.closest("button[data-id]");
        if (b && !b.disabled) {
            api("/api/status", { event_id: Number(b.dataset.id), status: b.dataset.status }).then(refresh);
            return;
        }
        const row = e.target.closest("tr[data-row]");
        if (row) openDrawer(Number(row.dataset.row));
    });
}

// ---------- Model Health ----------
let healthOpen = true;
async function loadHealth() {
    try {
        const h = await api("/api/health");
        if (!h.ready || !h.labelled) {
            $("healthTable").innerHTML = '<tr><td style="color:var(--text-muted);">No ground-truth labels available for current feed.</td></tr>';
            $("cmTable").innerHTML = "";
            return;
        }
        $("healthTable").innerHTML = "<thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>Support</th></tr></thead><tbody>" +
            h.classes.map((c, i) => `<tr><td><strong>${esc(c)}</strong></td><td><span class="mono">${num(h.precision[i])}</span></td><td><span class="mono">${num(h.recall[i])}</span></td><td><span class="mono">${h.support[i]}</span></td></tr>`).join("") + "</tbody>";
        $("cmTable").innerHTML = "<thead><tr><th></th>" + h.classes.map((c) => `<th>${esc(c)}</th>`).join("") + "</tr></thead><tbody>" +
            h.classes.map((row, i) => `<tr><th>${esc(row)}</th>` + h.matrix[i].map((v) =>
                `<td style="background:rgba(37,99,235,${(v * 0.7).toFixed(2)}); font-family:var(--font-mono);">${v >= 0.005 ? v.toFixed(2) : ""}</td>`).join("") + "</tr>").join("") + "</tbody>";
        if (typeof Chart !== "undefined") {
            if (!calibChart) {
                calibChart = new Chart($("calibChart"), {
                    type: "bar",
                    data: { labels: [], datasets: [{ label: "Accuracy", data: [], backgroundColor: "#2563eb", borderRadius: 2 }] },
                    options: { responsive: true, maintainAspectRatio: false, animation: false, scales: { y: { min: 0, max: 1 } } }
                });
            }
            calibChart.data.labels = h.calib.map((c) => `${c.bin} (n=${c.n})`);
            calibChart.data.datasets[0].data = h.calib.map((c) => c.accuracy);
            calibChart.update();
        }
    } catch (e) { console.warn("health failed:", e); }
}

if ($("healthBox")) {
    $("healthBox").addEventListener("toggle", () => {
        healthOpen = $("healthBox").open;
        if (healthOpen) loadHealth();
    });
}
setInterval(() => { if (healthOpen) loadHealth(); }, 6000);

// ---------- Logout Handler ----------
if ($("logoutBtn")) {
    $("logoutBtn").onclick = async () => {
        try {
            await fetch("/api/auth/logout", { method: "POST" });
        } finally {
            window.location.href = "/login.html";
        }
    };
}

// ---------- Start Application ----------
(async function start() {
    initTheme();
    const ok = await checkAuth();
    if (!ok) return;

    initRouting();
    initUserManagement();
    try { initCharts(); } catch (e) { console.warn("Charts unavailable:", e); }
    try {
        const days = await api("/api/days");
        if ($("day")) $("day").innerHTML = days.map((d) => `<option value="${esc(d)}">${esc(d)}</option>`).join("");
    } catch (e) { /* refresh displays error */ }
    initWebSocket();
    refresh();
    loadHealth();
    setInterval(refresh, 2000);
})();
