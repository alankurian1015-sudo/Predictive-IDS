const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (x, d = 2) => (x === null || x === undefined ? "n/a" : Number(x).toFixed(d));
const pct = (x, d = 0) => (x === null || x === undefined ? "n/a" : (x * 100).toFixed(d) + "%");
const COLORS = {
    Benign: "#2e9e6b", "DoS/DDoS": "#d64545", Recon: "#e08a1e", "Brute force": "#8a5cd6",
    "Web attack": "#2a7de1", Botnet: "#b83a8f", Infiltration: "#7a4a2a", Exploit: "#444444", Other: "#888888"
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
        badge.className = "role-badge " + currentUser.role;
    }
}

function applyRbacUI() {
    if (!currentUser) return;
    const isAdmin = currentUser.role === "admin";
    // Show/hide admin tabs
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
    document.querySelectorAll(".nav-tab").forEach((t) => {
        t.classList.toggle("active", t.dataset.tab === tabId);
    });
    document.querySelectorAll(".page-view").forEach((v) => {
        v.classList.add("hidden");
    });
    const target = $("view-" + tabId);
    if (target) target.classList.remove("hidden");
    window.location.hash = "#/" + tabId;

    if (tabId === "users" && currentUser?.role === "admin") {
        loadUsers();
    }
}

function initRouting() {
    const hash = (window.location.hash || "").replace("#/", "");
    const valid = ["live", "incidents", "models", "ingestion", "users"];
    const initial = valid.includes(hash) ? hash : "live";
    switchTab(initial);

    const tabs = $("navTabs");
    if (tabs) {
        tabs.addEventListener("click", (e) => {
            const btn = e.target.closest(".nav-tab");
            if (btn && btn.dataset.tab) {
                switchTab(btn.dataset.tab);
            }
        });
    }

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
                <td>${esc(u.id)}</td>
                <td><strong>${esc(u.username)}</strong></td>
                <td>${esc(u.full_name)}</td>
                <td><span class="role-badge ${esc(u.role)}">${esc(u.role.toUpperCase())}</span></td>
                <td>${u.last_login ? new Date(u.last_login).toLocaleString() : '<span class="meta">Never</span>'}</td>
                <td>${u.id !== currentUser.id && u.is_active ?
                    `<button class="btn-danger-outline" onclick="deactivateUser(${u.id})">Deactivate</button>` :
                    '<span class="meta">—</span>'}</td>
            </tr>
        `).join("");
    } catch (e) {
        console.warn("loadUsers failed:", e);
    }
}

window.deactivateUser = async (id) => {
    if (!confirm("Are you sure you want to deactivate this user account?")) return;
    try {
        const res = await fetch("/api/auth/users/" + id, { method: "DELETE" });
        if (res.ok) {
            loadUsers();
        } else {
            const d = await res.json();
            alert(d.detail || "Failed to deactivate user");
        }
    } catch (e) {
        alert("Network error: failed to deactivate user");
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
            msg.textContent = "Creating user…";
            try {
                const res = await fetch("/api/auth/users", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, password, full_name, role })
                });
                const d = await res.json();
                if (!res.ok) {
                    msg.textContent = d.detail || "Error creating user";
                    msg.style.color = "var(--bad)";
                } else {
                    msg.textContent = `User '${username}' created successfully!`;
                    msg.style.color = "var(--ok)";
                    form.reset();
                    loadUsers();
                }
            } catch (err) {
                msg.textContent = "Failed to create user";
                msg.style.color = "var(--bad)";
            }
        };
    }
}

// ---------- theming & real-time websocket ----------
function getPreferredTheme() {
    const saved = localStorage.getItem("pids-theme");
    if (saved === "dark" || saved === "light") return saved;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("pids-theme", theme);
    const isDark = theme === "dark";
    if ($("themeIcon")) $("themeIcon").textContent = isDark ? "☀️" : "🌙";
    if ($("themeLabel")) $("themeLabel").textContent = isDark ? "Light" : "Dark";

    const textColor = isDark ? "#c9d1d9" : "#1c2430";
    const gridColor = isDark ? "rgba(255, 255, 255, 0.08)" : "rgba(0, 0, 0, 0.06)";

    if (typeof Chart !== "undefined") {
        Chart.defaults.color = textColor;
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
            const cur = document.documentElement.getAttribute("data-theme") || "light";
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
        el.textContent = "● WS: LIVE";
        el.className = "pill pill-ws pulse";
        el.title = "Real-time WebSocket Live Feed Active";
    } else {
        el.textContent = "○ HTTP: POLLING";
        el.className = "pill pill-ws offline";
        el.title = "WebSocket Disconnected (HTTP Polling Active)";
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

// ---------- charts ----------
let trafficChart, familyChart, forecastChart, portsChart, histChart, calibChart;
let chartsOk = false;

function initCharts() {
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    const textColor = isDark ? "#c9d1d9" : "#1c2430";
    const gridColor = isDark ? "rgba(255, 255, 255, 0.08)" : "rgba(0, 0, 0, 0.06)";
    if (typeof Chart !== "undefined") {
        Chart.defaults.color = textColor;
    }
    const base = {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        scales: {
            x: { grid: { color: gridColor }, ticks: { color: textColor } },
            y: { grid: { color: gridColor }, ticks: { color: textColor } }
        }
    };
    trafficChart = new Chart($("trafficChart"), {
        type: "line", data: { labels: [], datasets: [] },
        options: {
            ...base, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } },
            plugins: { legend: { position: "bottom" } }
        }
    });
    familyChart = new Chart($("familyChart"), {
        type: "doughnut",
        data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
        options: { ...base, plugins: { legend: { position: "bottom" } } }
    });
    forecastChart = new Chart($("forecastChart"), {
        type: "line", data: { labels: [], datasets: [] },
        options: {
            ...base, spanGaps: false,
            scales: { y: { min: 0, max: 1, ticks: { callback: (v) => Math.round(v * 100) + "%" } } },
            plugins: { legend: { position: "bottom" } }
        }
    });
    portsChart = new Chart($("portsChart"), {
        type: "bar",
        data: { labels: [], datasets: [{ label: "attack flows", data: [], backgroundColor: "#e08a1e" }] },
        options: { ...base, plugins: { legend: { display: false } } }
    });
    histChart = new Chart($("histChart"), {
        type: "bar",
        data: { labels: [], datasets: [{ label: "flows", data: [], backgroundColor: "#2a7de1" }] },
        options: { ...base, plugins: { legend: { display: false } } }
    });
    chartsOk = true;
}

function updateCharts(s) {
    trafficChart.data.labels = s.traffic.labels;
    trafficChart.data.datasets = Object.entries(s.traffic.series).map(([fam, data]) => ({
        label: fam, data, fill: true, pointRadius: 0, borderWidth: 1,
        borderColor: COLORS[fam] || "#888", backgroundColor: (COLORS[fam] || "#888") + "99"
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
        $("histTitle").textContent = s.hist.ae ? "Anomaly score (1.0 = threshold)" : "Attack score (1 − P(benign))";
        histChart.data.labels = s.hist.edges.map((e) => e.toFixed(2));
        histChart.data.datasets[0].data = s.hist.counts;
        histChart.update();
    }
}

// ---------- rendering ----------
function kpiHtml(items) {
    return items.map(([l, v]) =>
        `<div class="kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");
}

function render(s) {
    $("status").textContent = s.live ? "LIVE" : "PAUSED";
    $("status").className = "pill" + (s.live ? " on" : "");
    $("meta").textContent = `${s.model}${s.autoencoder ? " + autoencoder" : ""} · queued: ${(s.queued ?? 0).toLocaleString()}` +
        ` · self-test agreement: ${pct(s.selftest, 1)} · ${s.versions ?? ""}`;
    $("healthWarn").textContent = s.held_out ? "" :
        "These replay rows may include data the models were trained on, so the numbers below are optimistic. Use them as a sanity check, not as test results.";
    const err = $("error");
    err.textContent = s.error || "";
    err.classList.toggle("hidden", !s.error);
    $("waiting").classList.toggle("hidden", s.has_data);

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
    $("kpis").innerHTML = kpiHtml(kpiItems);

    // live feed table
    $("feed").innerHTML = "<tr><th>ID</th><th>Time</th><th>Verdict</th><th>Family</th><th>Conf.</th><th>Source → Dest</th></tr>" +
        s.feed.map((r) => `<tr><td>${esc(r.event_id)}</td><td>${esc(r.capture_time)}</td>` +
            `<td class="verdict-${esc(r.verdict)}">${esc(r.verdict)}</td><td>${esc(r.predicted)}</td>` +
            `<td>${num(r.confidence)}</td><td>${esc(r.src_ip)} → ${esc(r.dst_ip)}:${esc(r.dst_port)}</td></tr>`).join("");

    if (chartsOk) updateCharts(s);

    // top IPs
    $("topIps").innerHTML = s.top_ips.map(([ip, n]) =>
        `<li><span class="mono">${esc(ip)}</span><span class="meta">${n.toLocaleString()} attacks</span></li>`).join("");

    renderForecast(s.forecast);

    // alert queue
    const isViewer = currentUser && currentUser.role === "viewer";
    const triageDisabled = isViewer ? 'disabled title="Viewer role cannot triage alerts (Analyst required)"' : '';
    $("queue").innerHTML = "<tr><th>ID</th><th>Severity</th><th>Status</th><th>Predicted</th><th>Conf.</th><th>Attack score</th><th>Anomaly</th><th>Flow</th><th>Actions</th></tr>" +
        s.queue.map((r) => `<tr data-row="${esc(r.event_id)}" title="${esc(r.top3)}" style="cursor:pointer">
      <td>${esc(r.event_id)}</td><td class="sev-${esc(r.severity)}">${esc(r.severity)}</td>
      <td>${esc(r.status)}</td><td>${esc(r.predicted)}</td><td>${num(r.confidence)}</td><td>${num(r.attack_score)}</td>
      <td>${num(r.anomaly_score)}</td><td>${esc(r.src_ip)} → ${esc(r.dst_ip)}:${esc(r.dst_port)}</td>
      <td><button data-id="${esc(r.event_id)}" data-status="Acknowledged" ${triageDisabled}>Ack</button>
          <button data-id="${esc(r.event_id)}" data-status="False positive" ${triageDisabled}>False pos.</button>
          <button data-id="${esc(r.event_id)}" data-status="Escalated" ${triageDisabled}>Escalate</button></td></tr>`).join("");
}

function renderForecast(fc) {
    if (!fc || !fc.ready) {
        $("fcNote").textContent = `Accumulating history… (${fc ? fc.buckets : 0} of 8 buckets)`;
        $("fcKpis").innerHTML = "";
        $("fcFamily").textContent = "";
        const w = $("warning");
        w.classList.add("hidden");
        return;
    }
    $("fcNote").textContent = `Risk level: ${fc.level} (trend: ${fc.trend})` +
        (fc.skill !== null ? ` · Forecast skill vs naïve: ${pct(fc.skill, 0)}` : "");

    const w = $("warning");
    if (fc.level === "High" || fc.trend === "Rising") {
        w.textContent = `Forecast warning: attack share is ${fc.level.toLowerCase()} and ${fc.trend.toLowerCase()}. ` +
            `Expected share over the next 60 s: ${pct(fc.next, 1)}.`;
        w.classList.remove("hidden");
    } else {
        w.classList.add("hidden");
    }

    $("fcKpis").innerHTML = kpiHtml([
        ["Current share (~30 s)", pct(fc.now, 1)],
        ["Next 30 s forecast", pct(fc.next30, 1)],
        ["Next 60 s avg", pct(fc.next, 1)],
        ["Risk level", fc.level],
    ]);

    if (chartsOk) {
        forecastChart.data.labels = fc.labels;
        forecastChart.data.datasets = [
            {
                label: "Observed attack share",
                data: fc.observed.concat(Array(fc.forecast.length).fill(null)),
                borderColor: "#2a7de1", backgroundColor: "rgba(42, 125, 225, 0.15)",
                fill: false, tension: 0.2
            },
            {
                label: "Holt forecast",
                data: Array(fc.observed.length - 1).fill(null).concat([fc.observed[fc.observed.length - 1]]).concat(fc.forecast),
                borderColor: "#d64545", backgroundColor: "rgba(214, 69, 69, 0.15)",
                borderDash: [5, 5], fill: false, tension: 0.2
            }
        ];
        forecastChart.update();
    }

    $("fcFamily").textContent = fc.top_family
        ? `Likely dominant attack family: ${fc.top_family} (${pct(fc.top_family_share, 0)} of recent attacks)`
        : "Likely next attack family: none in the last 60 s.";
}

// ---------- polling ----------
let busy = false, synced = false;

function syncBoxes() {
    if ($("watchBox")) $("watchBox").classList.toggle("hidden", $("source").value !== "watch");
    if ($("uploadBox")) $("uploadBox").classList.toggle("hidden", $("source").value !== "upload");
}

async function refresh() {
    if (busy || document.hidden) return;           // no polling while tab is hidden
    busy = true;
    try {
        const sev = [...document.querySelectorAll(".sev:checked")].map((c) => c.value).join(",");
        const fams = [...document.querySelectorAll(".fam:checked")].map((c) => c.value).join(",") || "__none__";
        const s = await api(`/api/state?min_conf=${$("minConf").value}&sev=${encodeURIComponent(sev)}&fams=${encodeURIComponent(fams)}`);
        if (!synced) {                             // copy server's settings into controls once
            $("live").checked = s.live;
            if ($("rate")) $("rate").value = s.rate;
            if ($("source")) $("source").value = s.source;
            if ($("watchPath")) $("watchPath").value = s.watch_path;
            syncBoxes();
            synced = true;
        }
        render(s);
    } catch (e) {
        if (e.message !== "401 Unauthorized") {
            $("error").textContent = "Cannot reach server: " + e.message;
            $("error").classList.remove("hidden");
        }
    } finally { busy = false; }
}

// ---------- controls ----------
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
        `<label class="row"><input type="checkbox" class="fam" value="${esc(f)}" checked> ${esc(f)}</label>`).join("");
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

// ---------- upload ----------
if ($("uploadFile")) {
    $("uploadFile").onchange = async () => {
        const f = $("uploadFile").files[0];
        if (!f) return;
        $("uploadMsg").textContent = "Uploading…";
        const fd = new FormData();
        fd.append("file", f);
        try {
            const res = await fetch("/api/upload", { method: "POST", body: fd });
            const r = await res.json();
            $("uploadMsg").textContent = r.ok ? `${r.queued.toLocaleString()} flows queued` : (r.error || "Upload failed");
        } catch (e) { $("uploadMsg").textContent = "Upload failed: " + e.message; }
        refresh();
    };
}

// ---------- investigate drawer ----------
async function openDrawer(id) {
    let r;
    try { r = await api("/api/alert/" + id); } catch (e) { return; }
    if (!r.found) return;
    const top3 = String(r.top3 || "").split(" | ").map((t) => `<li>${esc(t)}</li>`).join("");
    const isViewer = currentUser && currentUser.role === "viewer";
    const triageDisabled = isViewer ? 'disabled title="Viewer role cannot triage alerts (Analyst required)"' : '';

    $("drawerBody").innerHTML = `
    <h3>Alert #${esc(r.event_id)} · <span class="sev-${esc(r.severity)}">${esc(r.severity)}</span></h3>
    <dl>
      <dt>Verdict</dt><dd>${esc(r.verdict)}</dd>
      <dt>Predicted</dt><dd>${esc(r.predicted)} (${esc(r.family)})</dd>
      <dt>Confidence</dt><dd>${num(r.confidence)}</dd>
      <dt>Attack score</dt><dd>${num(r.attack_score)}</dd>
      <dt>Anomaly score</dt><dd>${num(r.anomaly_score)}</dd>
      <dt>Uncertainty</dt><dd>${num(r.uncertainty)}</dd>
      <dt>Flow</dt><dd>${esc(r.src_ip)} → ${esc(r.dst_ip)}:${esc(r.dst_port)}</dd>
      <dt>Capture time</dt><dd>${esc(r.capture_time)}</dd>
      <dt>Status</dt><dd>${esc(r.status)}</dd>
      <dt>Ground truth</dt><dd>${esc(r.actual)} <span class="meta">(replay only)</span></dd>
    </dl>
    <h3>Top-3 classes</h3><ul>${top3}</ul>
    <button data-id="${esc(r.event_id)}" data-status="Acknowledged" ${triageDisabled}>Acknowledge</button>
    <button data-id="${esc(r.event_id)}" data-status="False positive" ${triageDisabled}>False positive</button>
    <button data-id="${esc(r.event_id)}" data-status="Escalated" ${triageDisabled}>Escalate</button>`;
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

// ---------- model health ----------
let healthOpen = true;
async function loadHealth() {
    try {
        const h = await api("/api/health");
        if (!h.ready || !h.labelled) {
            $("healthTable").innerHTML = '<tr><td class="meta">No labelled flows yet (live and uploaded feeds carry no ground truth).</td></tr>';
            $("cmTable").innerHTML = "";
            return;
        }
        $("healthTable").innerHTML = "<tr><th>Class</th><th>Precision</th><th>Recall</th><th>Support</th></tr>" +
            h.classes.map((c, i) => `<tr><td>${esc(c)}</td><td>${num(h.precision[i])}</td><td>${num(h.recall[i])}</td><td>${h.support[i]}</td></tr>`).join("");
        $("cmTable").innerHTML = "<tr><th></th>" + h.classes.map((c) => `<th>${esc(c)}</th>`).join("") + "</tr>" +
            h.classes.map((row, i) => `<tr><th>${esc(row)}</th>` + h.matrix[i].map((v) =>
                `<td style="background:rgba(42,125,225,${v.toFixed(2)})">${v >= 0.005 ? v.toFixed(2) : ""}</td>`).join("") + "</tr>").join("");
        if (typeof Chart !== "undefined") {
            if (!calibChart) {
                calibChart = new Chart($("calibChart"), {
                    type: "bar",
                    data: { labels: [], datasets: [{ label: "accuracy", data: [], backgroundColor: "#2a7de1" }] },
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

// ---------- logout handler ----------
if ($("logoutBtn")) {
    $("logoutBtn").onclick = async () => {
        try {
            await fetch("/api/auth/logout", { method: "POST" });
        } finally {
            window.location.href = "/login.html";
        }
    };
}

// ---------- start application ----------
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
