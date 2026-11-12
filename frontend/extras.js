// extras.js: incidents, MITRE ATT&CK kill-chain progression, and model-explanation panels.
// Loaded after app.js, which defines $, esc, num, pct, api and refresh().

function renderKillChainOverview(stages) {
    const box = $("killChainOverview");
    if (!box) return;
    if (!stages || !stages.length) {
        box.innerHTML = "";
        return;
    }
    const descs = {
        1: "PortScan, probes & sweeps",
        2: "Brute force & credentials",
        3: "Web exploit, SQLi & XSS",
        4: "Botnet C2 & lateral pivot",
        5: "DoS/DDoS & exfiltration"
    };
    box.innerHTML = stages.map((s) => {
        const active = s.count > 0;
        return `
        <div class="kc-stage-card stage-${s.num} ${active ? 'has-threats' : ''}">
            <div class="kc-stage-header">
                <span class="kc-stage-num">Stage ${s.num}</span>
                <span class="kc-stage-badge">${s.count} ${s.count === 1 ? 'threat' : 'threats'}</span>
            </div>
            <div class="kc-stage-title">${esc(s.name)}</div>
            <div class="kc-stage-desc">${esc(descs[s.num] || '')}</div>
        </div>`;
    }).join("");
}

function renderStepper(pred) {
    if (!pred || !pred.next_vector) return '<span class="meta">—</span>';
    const curr = pred.stage_num || 1;
    const next = pred.next_stage_num || Math.min(5, curr + 1);

    const nodes = [1, 2, 3, 4, 5].map((n) => {
        let cls = "kc-node";
        let title = "";
        if (n === curr) {
            cls += ` stage-${n} active`;
            title = `Current stage: ${pred.stage}`;
        } else if (n === next) {
            cls += ` next`;
            title = `Predicted next stage: ${pred.next_stage || 'Next'}`;
        }
        return `<span class="${cls}" title="${esc(title)}">${n}</span>`;
    }).join('<span class="kc-node-arrow">›</span>');

    return `
    <div class="kc-stepper-track">
        <div class="kc-stepper-nodes" title="Adversary Stage Progression: ${esc(pred.stage)} ➔ ${esc(pred.next_stage || 'Next')}">${nodes}</div>
        <span class="pred-pill" title="Stage: ${esc(pred.stage)} ➔ ${esc(pred.next_stage || '')}&#10;Action: ${esc(pred.action)}">
            <span class="pred-badge">🔮 ${esc(pred.next_vector)}</span>
            <span class="pred-meta" style="font-family:var(--font-mono); font-size:10px;">${Math.round(pred.confidence * 100)}% · ${esc(pred.eta)}</span>
        </span>
        ${pred.action ? `<span class="kc-action-pill" title="Proactive SOC Countermeasure: ${esc(pred.action)}">🛡️ ${esc(pred.action)}</span>` : ''}
    </div>`;
}

// ---------- Incidents ----------
async function loadIncidents() {
    if (document.hidden) return;
    try {
        const d = await api("/api/incidents");
        $("incSummary").textContent = d.incidents_total
            ? `${d.alerts_total.toLocaleString()} threat flows correlated into ${d.incidents_total.toLocaleString()} adversary campaigns ` +
            `(${(d.alerts_total / d.incidents_total).toFixed(1)} flows/campaign)`
            : "No active adversary campaigns detected.";

        renderKillChainOverview(d.stage_summary);

        const badge = $("incNavBadge");
        if (badge) {
            if (d.incidents_total > 0) {
                badge.textContent = d.incidents_total;
                badge.classList.remove("hidden");
            } else {
                badge.classList.add("hidden");
            }
        }

        const isViewer = window.currentUser && window.currentUser.role === "viewer";
        const triageDisabled = isViewer ? 'disabled title="Viewer role cannot triage alerts (Analyst required)"' : '';

        $("incidents").innerHTML = d.incidents.length
            ? "<tr><th>Severity</th><th>Hostile Source</th><th>Attack Type</th><th>Kill-Chain & Predicted Next Vector</th><th>Flows</th><th>Target Footprint</th><th>First</th><th>Last</th><th>Duration</th><th>Campaign Status</th><th>Actions</th></tr>" +
            d.incidents.map((r) => {
                const a = `data-ip="${esc(r.src_ip)}" data-fam="${esc(r.family)}" data-first="${esc(r.first_id)}" data-last="${esc(r.last_id)}"`;
                const predHtml = renderStepper(r.prediction);
                return `<tr>
                    <td><span class="inc-sev-${esc(r.severity)}">${esc(r.severity)}</span></td>
                    <td><span class="mono" style="color:var(--accent); font-weight:700;">${esc(r.src_ip)}</span></td>
                    <td><strong>${esc(r.label)}</strong> <span class="meta">(${esc(r.family)})</span></td>
                    <td class="pred-cell">${predHtml}</td>
                    <td><span class="soc-tier-badge">${r.n.toLocaleString()}</span></td>
                    <td><span class="mono" style="font-size:11px;">${r.dst_ips} IPs · ${r.dst_ports} ports</span></td>
                    <td><span class="mono" style="color:var(--muted);">${esc(r.first)}</span></td>
                    <td><span class="mono" style="color:var(--muted);">${esc(r.last)}</span></td>
                    <td><span class="mono">${Math.round(r.duration_s)}s</span></td>
                    <td><span class="soc-tier-badge" style="background:var(--input-bg);">${esc(r.status)}</span></td>
                    <td>
                        <button ${a} data-status="Acknowledged" ${triageDisabled}>✓ Ack</button>
                        <button ${a} data-status="False positive" ${triageDisabled}>⊘ False pos.</button>
                        <button ${a} data-status="Escalated" ${triageDisabled} style="color:var(--bad); border-color:rgba(239,68,68,0.3);">▲ Escalate</button>
                    </td>
                </tr>`;
            }).join("")
            : "";
    } catch (e) { /* connection error handled in refresh */ }
}

window.loadIncidents = loadIncidents;

if ($("incidents")) {
    $("incidents").addEventListener("click", async (e) => {
        const b = e.target.closest("button[data-ip]");
        if (!b || b.disabled) return;
        try {
            await api("/api/incident/status", {
                src_ip: b.dataset.ip, family: b.dataset.fam,
                first_id: Number(b.dataset.first), last_id: Number(b.dataset.last), status: b.dataset.status
            });
        } catch (err) { alert("Could not update the incident: " + err.message); }
        loadIncidents();
        refresh();
    });
}
setInterval(loadIncidents, 3000);
loadIncidents();

// ---------- Feature Importance ----------
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
    if (!$("shapMethod")) return;
    const kernel = $("shapMethod").value === "kernel";
    document.querySelectorAll(".kOnly").forEach((e) => e.classList.toggle("hidden", !kernel));
    document.querySelectorAll(".tOnly").forEach((e) => e.classList.toggle("hidden", kernel));
}

function renderShap() {
    const d = explainData;
    if (!d) return;
    if ($("impBuiltin")) $("impBuiltin").innerHTML = impList(d.builtin);
    const sel = $("shapClass");
    if (d.shap && sel && sel.options.length <= 1) {
        Object.keys(d.shap.per_class).forEach((c) => sel.add(new Option(c, c)));
    }
    const running = d.status === "running";
    if ($("shapMsg")) {
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
    }
    if ($("shapRun")) $("shapRun").disabled = running;
    if ($("shapStop")) $("shapStop").classList.toggle("hidden", !(running && $("shapMethod").value === "kernel"));
    const rows = d.shap ? (sel && sel.value ? d.shap.per_class[sel.value] : d.shap.global) : null;
    if ($("impShap")) $("impShap").innerHTML = d.shap ? impList(rows) : "";
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

if ($("shapMethod")) $("shapMethod").onchange = () => { syncMethod(); renderShap(); };
if ($("shapRun")) {
    $("shapRun").onclick = async () => {
        const r = await api("/api/explain/run", {
            method: $("shapMethod").value, n: Number($("shapN").value), trees: Number($("shapTrees").value),
            nsamples: Number($("shapNs").value), budget: Number($("shapBudget").value)
        });
        if (!r.ok) alert(r.error);
        loadExplain();
    };
}
if ($("shapStop")) $("shapStop").onclick = () => api("/api/explain/cancel", {}).then(loadExplain);
if ($("shapClass")) $("shapClass").onchange = renderShap;
syncMethod();
loadExplain();
