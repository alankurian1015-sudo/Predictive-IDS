// extras.js: incidents and feature-importance panels.
// Loaded after app.js, which defines $, esc, num, pct, api and refresh().

// ---------- incidents ----------
async function loadIncidents() {
    if (document.hidden) return;
    try {
        const d = await api("/api/incidents");
        $("incSummary").textContent = d.incidents_total
            ? `${d.alerts_total.toLocaleString()} attack alerts grouped into ${d.incidents_total.toLocaleString()} incidents ` +
            `(${(d.alerts_total / d.incidents_total).toFixed(1)} alerts per incident)`
            : "No attack incidents yet.";
        $("incidents").innerHTML = d.incidents.length
            ? "<tr><th>Severity</th><th>Source</th><th>Type</th><th>Alerts</th><th>Targets</th><th>First</th><th>Last</th><th>Duration</th><th>Status</th><th>Actions</th></tr>" +
            d.incidents.map((r) => {
                const a = `data-ip="${esc(r.src_ip)}" data-fam="${esc(r.family)}" data-first="${esc(r.first_id)}" data-last="${esc(r.last_id)}"`;
                return `<tr><td class="inc-sev-${esc(r.severity)}">${esc(r.severity)}</td><td>${esc(r.src_ip)}</td>
            <td>${esc(r.label)} <span class="meta">(${esc(r.family)})</span></td><td>${r.n.toLocaleString()}</td>
            <td>${r.dst_ips} IPs · ${r.dst_ports} ports</td><td>${esc(r.first)}</td><td>${esc(r.last)}</td>
            <td>${Math.round(r.duration_s)} s</td><td>${esc(r.status)}</td>
            <td><button ${a} data-status="Acknowledged">Ack</button>
                <button ${a} data-status="False positive">False pos.</button>
                <button ${a} data-status="Escalated">Escalate</button></td></tr>`;
            }).join("")
            : "";
    } catch (e) { /* the main refresh already shows connection problems */ }
}

$("incidents").addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-ip]");
    if (!b) return;
    try {
        await api("/api/incident/status", {
            src_ip: b.dataset.ip, family: b.dataset.fam,
            first_id: Number(b.dataset.first), last_id: Number(b.dataset.last), status: b.dataset.status
        });
    } catch (err) { alert("Could not update the incident: " + err.message); }
    loadIncidents();
    refresh();
});
setInterval(loadIncidents, 3000);
loadIncidents();

// ---------- feature importance ----------
let explainData = null, explainTimer = null;

function impList(rows) {
    if (!rows || !rows.length) return '<p class="meta">Not available.</p>';
    const top = rows[0].share || 1;
    return '<ol class="imp">' + rows.map((r) =>
        `<li><span class="name" title="${esc(r.feature)}">${esc(r.feature)}</span>` +
        `<span class="bar"><i style="width:${Math.max(2, Math.round((r.share / top) * 100))}%"></i></span>` +
        `<span class="pctv">${(r.share * 100).toFixed(1)}%</span></li>`).join("") + "</ol>";
}

function syncMethod() {
    const kernel = $("shapMethod").value === "kernel";
    document.querySelectorAll(".kOnly").forEach((e) => e.classList.toggle("hidden", !kernel));
    document.querySelectorAll(".tOnly").forEach((e) => e.classList.toggle("hidden", kernel));
}

function renderShap() {
    const d = explainData;
    if (!d) return;
    $("impBuiltin").innerHTML = impList(d.builtin);
    const sel = $("shapClass");
    if (d.shap && sel.options.length <= 1) {
        Object.keys(d.shap.per_class).forEach((c) => sel.add(new Option(c, c)));
    }
    const running = d.status === "running";
    if (running) {
        const p = d.progress;
        $("shapMsg").textContent = p ? `Computing… ${p.done}/${p.total} flows` : "Computing… (preparing the sample)";
    } else if (d.status === "error") {
        $("shapMsg").textContent = d.error;
    } else if (d.status === "done" && d.shap) {
        const r = d.shap;
        const how = r.method === "kernel" ? `Kernel SHAP, ${r.nsamples} evaluations per flow`
            : (r.trees ? `Tree SHAP, first ${r.trees} trees` : "Tree SHAP, all trees");
        $("shapMsg").textContent = `Done in ${d.seconds} s: ${how}, ${r.n} attack flows, benign excluded` +
            (r.partial ? ` (stopped early: ${r.n} of ${r.planned} planned flows)` : "") + ".";
    } else {
        $("shapMsg").textContent = "Click “Compute SHAP” (runs in the background).";
    }
    $("shapRun").disabled = running;
    $("shapStop").classList.toggle("hidden", !(running && $("shapMethod").value === "kernel"));
    const rows = d.shap ? (sel.value ? d.shap.per_class[sel.value] : d.shap.global) : null;
    $("impShap").innerHTML = d.shap ? impList(rows) : "";
}

async function loadExplain() {
    try {
        explainData = await api("/api/explain");
        renderShap();
        if (explainData.status === "running" && !explainTimer) {
            explainTimer = setInterval(loadExplain, 1500);
        }
        if (explainData.status !== "running" && explainTimer) {
            clearInterval(explainTimer);
            explainTimer = null;
        }
    } catch (e) { /* ignore */ }
}

$("shapMethod").onchange = () => { syncMethod(); renderShap(); };
$("shapRun").onclick = async () => {
    const r = await api("/api/explain/run", {
        method: $("shapMethod").value, n: Number($("shapN").value), trees: Number($("shapTrees").value),
        nsamples: Number($("shapNs").value), budget: Number($("shapBudget").value)
    });
    if (!r.ok) alert(r.error);
    loadExplain();
};
$("shapStop").onclick = () => api("/api/explain/cancel", {}).then(loadExplain);
$("shapClass").onchange = renderShap;
syncMethod();
loadExplain();