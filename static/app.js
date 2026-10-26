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

async function api(path, body) {
    const opts = body !== undefined
        ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
        : undefined;
    const res = await fetch(path, opts);
    if (!res.ok) throw new Error(res.status + " " + path);
    return res.json();
}

// ---------- charts ----------
let trafficChart, familyChart, forecastChart, portsChart, histChart, calibChart;
let chartsOk = false;

function initCharts() {
    const base = { responsive: true, maintainAspectRatio: false, animation: false };
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

    const k = s.kpi;
    $("kpis").innerHTML = kpiHtml([
        ["Events seen (total)", s.total.toLocaleString()], ["Attack rate", pct(k.attack_rate, 1)],
        ["Open critical", k.open_critical], ["Escalated", k.escalated],
        ["Avg confidence", num(k.avg_conf)], ["Anomalies (>1.0)", k.anomalies ?? "n/a"],
    ]);

    // live feed
    const vClass = { Genuine: "v-genuine", Malicious: "v-malicious", Suspicious: "v-suspicious" };
    const vIcon = { Genuine: "✅ ", Malicious: "🚨 ", Suspicious: "⚠️ " };
    $("feed").innerHTML = "<tr><th>ID</th><th>Capture time</th><th>Source</th><th>Destination</th><th>Verdict</th><th>Predicted</th><th>Confidence</th></tr>" +
        s.feed.map((r) => `<tr><td>${esc(r.event_id)}</td><td>${esc(r.capture_time)}</td><td>${esc(r.src_ip)}</td>
      <td>${esc(r.dst_ip)}:${esc(r.dst_port)}</td><td class="${vClass[r.verdict] || ""}">${vIcon[r.verdict] || ""}${esc(r.verdict)}</td>
      <td>${esc(r.predicted)}</td><td><span class="bar"><i style="width:${Math.round(r.confidence * 100)}%"></i></span>${num(r.confidence)}</td></tr>`).join("");

    if (chartsOk) updateCharts(s);

    $("topIps").innerHTML = s.top_ips.length
        ? s.top_ips.map(([ip, n]) => `<li>${esc(ip)} <span class="meta">(${n})</span></li>`).join("")
        : '<li class="meta">No attacks detected yet</li>';

    renderForecast(s.forecast);

    // alert queue
    $("queue").innerHTML = "<tr><th>ID</th><th>Severity</th><th>Status</th><th>Predicted</th><th>Conf.</th><th>Attack score</th><th>Anomaly</th><th>Flow</th><th>Actions</th></tr>" +
        s.queue.map((r) => `<tr data-row="${esc(r.event_id)}" title="${esc(r.top3)}" style="cursor:pointer">
      <td>${esc(r.event_id)}</td><td class="sev-${esc(r.severity)}">${esc(r.severity)}</td>
      <td>${esc(r.status)}</td><td>${esc(r.predicted)}</td><td>${num(r.confidence)}</td><td>${num(r.attack_score)}</td>
      <td>${num(r.anomaly_score)}</td><td>${esc(r.src_ip)} → ${esc(r.dst_ip)}:${esc(r.dst_port)}</td>
      <td><button data-id="${esc(r.event_id)}" data-status="Acknowledged">Ack</button>
          <button data-id="${esc(r.event_id)}" data-status="False positive">False pos.</button>
          <button data-id="${esc(r.event_id)}" data-status="Escalated">Escalate</button></td></tr>`).join("");
}

function renderForecast(f) {
    const warn = $("warning");
    if (!f || !f.ready) {
        $("fcNote").textContent = `Collecting history… ${f ? f.buckets : 0}/8 ten-second buckets ` +
            "(about 80 s of live traffic needed, or use “Fast-forward 2 min” in replay mode).";
        $("fcKpis").innerHTML = "";
        $("fcFamily").textContent = "";
        warn.classList.add("hidden");
        if (chartsOk) { forecastChart.data.labels = []; forecastChart.data.datasets = []; forecastChart.update(); }
        return;
    }
    $("fcNote").textContent = "";
    $("fcKpis").innerHTML = kpiHtml([
        ["Risk level", f.level], ["Trend", f.trend], ["Attack share now", pct(f.now)],
        ["Forecast (next 60 s)", pct(f.next)],
        ["Skill vs naive", f.skill === null || f.skill === undefined ? "n/a" : (f.skill >= 0 ? "+" : "") + Math.round(f.skill * 100) + "%"],
    ]);
    const alarm = (f.level === "High" || f.level === "Severe") && f.trend !== "Falling";
    warn.classList.toggle("hidden", !alarm);
    if (alarm) {
        warn.textContent = `Early warning (${f.level}, ${f.trend.toLowerCase()}): attack share is ${pct(f.now)} now and forecast at ${pct(f.next30)} over the next 30 s.` +
            (f.top_family ? ` Dominant family: ${f.top_family}.` : "");
    }
    if (chartsOk) {
        const n = f.observed.length, m = f.forecast.length;
        forecastChart.data.labels = f.labels;
        forecastChart.data.datasets = [
            { label: "observed", data: [...f.observed, ...Array(m).fill(null)], borderColor: "#2a7de1", pointRadius: 0, tension: 0.2 },
            {
                label: "forecast", data: [...Array(n - 1).fill(null), f.observed[n - 1], ...f.forecast],
                borderColor: "#d64545", borderDash: [6, 4], pointRadius: 0, tension: 0.2
            },
        ];
        forecastChart.update();
    }
    $("fcFamily").textContent = f.top_family
        ? `Likely next attack family: ${f.top_family} (${pct(f.top_family_share)} of attacks in the last 60 s). This is a persistence estimate, not a trained model.`
        : "Likely next attack family: none in the last 60 s.";
}

// ---------- polling ----------
let busy = false, synced = false;

function syncBoxes() {
    $("watchBox").classList.toggle("hidden", $("source").value !== "watch");
    $("uploadBox").classList.toggle("hidden", $("source").value !== "upload");
}

async function refresh() {
    if (busy || document.hidden) return;           // no polling while the tab is in the background
    busy = true;
    try {
        const sev = [...document.querySelectorAll(".sev:checked")].map((c) => c.value).join(",");
        const fams = [...document.querySelectorAll(".fam:checked")].map((c) => c.value).join(",") || "__none__";
        const s = await api(`/api/state?min_conf=${$("minConf").value}&sev=${encodeURIComponent(sev)}&fams=${encodeURIComponent(fams)}`);
        if (!synced) {                                     // copy the server's settings into the controls once
            $("live").checked = s.live;
            $("rate").value = s.rate;
            $("source").value = s.source;
            $("watchPath").value = s.watch_path;
            syncBoxes();
            synced = true;
        }
        render(s);
    } catch (e) {
        $("error").textContent = "Cannot reach the server: " + e.message;
        $("error").classList.remove("hidden");
    } finally { busy = false; }
}

// ---------- controls ----------
$("live").onchange = () => api("/api/control", { live: $("live").checked }).then(refresh);
$("rate").onchange = () => api("/api/control", { rate: parseInt($("rate").value, 10) || 20 });
$("source").onchange = () => {
    syncBoxes();
    api("/api/control", { source: $("source").value }).then(refresh);
};
$("watchPath").onchange = () => api("/api/control", { watch_path: $("watchPath").value })
    .then((r) => { if (!r.ok) alert(r.error); });
$("jump").onclick = () => api("/api/jump", { day: $("day").value })
    .then((r) => { if (!r.ok) alert(r.error); });
$("clear").onclick = () => api("/api/clear", {}).then(refresh);
let confTimer = null;
$("minConf").oninput = () => {
    $("minConfVal").textContent = Number($("minConf").value).toFixed(2);
    clearTimeout(confTimer);                       // wait for the slider to settle instead of one request per pixel
    confTimer = setTimeout(refresh, 200);
};
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
document.querySelectorAll(".sev").forEach((c) => (c.onchange = refresh));

$("famBox").innerHTML = FAMILIES.map((f) =>
    `<label class="row"><input type="checkbox" class="fam" value="${esc(f)}" checked> ${esc(f)}</label>`).join("");
$("famBox").addEventListener("change", refresh);

$("ff").onclick = async () => {
    $("ff").disabled = true;
    try {
        const r = await api("/api/fastforward", { ticks: 60 });
        if (!r.ok) alert(r.error);
    } catch (e) { alert("Fast-forward failed: " + e.message); }
    finally { $("ff").disabled = false; refresh(); }
};

// ---------- upload ----------
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

// ---------- investigate drawer ----------
async function openDrawer(id) {
    let r;
    try { r = await api("/api/alert/" + id); } catch (e) { return; }
    if (!r.found) return;
    const top3 = String(r.top3 || "").split(" | ").map((t) => `<li>${esc(t)}</li>`).join("");
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
    <button data-id="${esc(r.event_id)}" data-status="Acknowledged">Acknowledge</button>
    <button data-id="${esc(r.event_id)}" data-status="False positive">False positive</button>
    <button data-id="${esc(r.event_id)}" data-status="Escalated">Escalate</button>`;
    $("drawer").classList.remove("hidden");
}
$("drawerClose").onclick = () => $("drawer").classList.add("hidden");
$("drawer").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-id]");
    if (b) {
        api("/api/status", { event_id: Number(b.dataset.id), status: b.dataset.status })
            .then(() => { refresh(); openDrawer(Number(b.dataset.id)); });
    }
});
$("queue").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-id]");
    if (b) {
        api("/api/status", { event_id: Number(b.dataset.id), status: b.dataset.status }).then(refresh);
        return;
    }
    const row = e.target.closest("tr[data-row]");
    if (row) openDrawer(Number(row.dataset.row));
});

// ---------- model health ----------
let healthOpen = false;
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
$("healthBox").addEventListener("toggle", () => {
    healthOpen = $("healthBox").open;
    if (healthOpen) loadHealth();
});
setInterval(() => { if (healthOpen) loadHealth(); }, 6000);

// ---------- start ----------
(async function start() {
    try { initCharts(); } catch (e) { console.warn("Charts unavailable:", e); }
    try {
        const days = await api("/api/days");
        $("day").innerHTML = days.map((d) => `<option value="${esc(d)}">${esc(d)}</option>`).join("");
    } catch (e) { /* the first refresh shows the error */ }
    refresh();
    setInterval(refresh, 2000);
})();