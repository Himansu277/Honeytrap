// ==============================================================================
// HoneyTrap - Threat Intelligence Dashboard Client Logic
// ==============================================================================

let countryChart = null;
let passwordChart = null;

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    pollData();
    setInterval(pollData, 3000);
});

function initCharts() {
    const ctxCountry = document.getElementById("countryChart").getContext("2d");
    countryChart = new Chart(ctxCountry, {
        type: "bar",
        data: {
            labels: [],
            datasets: [{
                label: "Attacks by Country",
                data: [],
                backgroundColor: [
                    "rgba(59, 130, 246, 0.7)",
                    "rgba(239, 68, 68, 0.7)",
                    "rgba(245, 158, 11, 0.7)",
                    "rgba(16, 185, 129, 0.7)",
                    "rgba(139, 92, 246, 0.7)"
                ],
                borderColor: "rgba(255, 255, 255, 0.1)",
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#94a3b8" } },
                x: { grid: { display: false }, ticks: { color: "#94a3b8" } }
            }
        }
    });

    const ctxPass = document.getElementById("passwordChart").getContext("2d");
    passwordChart = new Chart(ctxPass, {
        type: "doughnut",
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    "#f59e0b",
                    "#ef4444",
                    "#3b82f6",
                    "#10b981",
                    "#8b5cf6"
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: "right", labels: { color: "#cbd5e1", boxWidth: 12 } }
            }
        }
    });
}

async function pollData() {
    try {
        const [statsRes, attacksRes, cmdsRes, alertsRes] = await Promise.all([
            fetch("/api/stats"),
            fetch("/api/attacks"),
            fetch("/api/commands"),
            fetch("/api/alerts")
        ]);

        const stats = await statsRes.json();
        const attacks = await attacksRes.json();
        const commands = await cmdsRes.json();
        const alerts = await alertsRes.json();

        updateStats(stats);
        updateAttacksTable(attacks);
        updateTerminalStream(commands);
        updateAlerts(alerts);
    } catch (err) {
        console.error("Error fetching telemetry:", err);
    }
}

function updateStats(stats) {
    document.getElementById("statTotalEvents").innerText = stats.total_events || 0;
    document.getElementById("statUniqueIPs").innerText = stats.unique_ips || 0;
    document.getElementById("statLogins").innerText = (stats.logins_failed || 0) + (stats.logins_success || 0);
    document.getElementById("statLoginRatio").innerText = `${stats.logins_failed || 0} Failed / ${stats.logins_success || 0} Succeeded`;
    document.getElementById("statCommands").innerText = stats.commands_typed || 0;

    // Update Status Banner
    const status = stats.system_status || {};
    const banner = document.getElementById("statusBanner");
    const headline = document.getElementById("statusHeadline");
    const badge = document.getElementById("stateBadge");
    const icon = document.getElementById("statusIcon");
    const iconContainer = document.getElementById("statusIconContainer");
    const updatedTime = document.getElementById("lastUpdatedTime");

    headline.innerText = status.status_text || "HoneyTrap is ARMED.";
    updatedTime.innerText = status.last_healing_event || "Active";

    if (status.state === "UNDER_ATTACK") {
        banner.className = "p-6 rounded-2xl border border-red-500/50 bg-red-950/30 backdrop-blur flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all duration-300 attack-pulse";
        badge.className = "px-2.5 py-1 text-xs font-bold uppercase tracking-wider rounded-full bg-red-500/20 text-red-300 border border-red-500/40";
        badge.innerText = "CRITICAL: INTRUSION ACTIVE";
        icon.className = "fa-solid fa-triangle-exclamation";
        iconContainer.className = "p-3 rounded-xl bg-red-500/20 text-red-400 border border-red-500/30 text-2xl";
    } else if (status.state === "SELF_HEALING" || status.state === "REBUILDING") {
        banner.className = "p-6 rounded-2xl border border-amber-500/50 bg-amber-950/30 backdrop-blur flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all duration-300";
        badge.className = "px-2.5 py-1 text-xs font-bold uppercase tracking-wider rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40";
        badge.innerText = "SELF-HEALING IN PROGRESS";
        icon.className = "fa-solid fa-arrows-spin fa-spin";
        iconContainer.className = "p-3 rounded-xl bg-amber-500/20 text-amber-400 border border-amber-500/30 text-2xl";
    } else if (status.state === "SERVICE_STOPPED" || status.state === "HEALING_FAILED") {
        banner.className = "p-6 rounded-2xl border border-red-500/50 bg-red-950/30 backdrop-blur flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all duration-300";
        badge.className = "px-2.5 py-1 text-xs font-bold uppercase tracking-wider rounded-full bg-red-500/20 text-red-300 border border-red-500/40";
        badge.innerText = status.state === "HEALING_FAILED" ? "HEALING FAILED" : "SERVICE OFFLINE";
        icon.className = "fa-solid fa-circle-exclamation";
        iconContainer.className = "p-3 rounded-xl bg-red-500/20 text-red-400 border border-red-500/30 text-2xl";
    } else {
        banner.className = "p-6 rounded-2xl border border-emerald-500/30 bg-emerald-950/20 backdrop-blur flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all duration-300";
        badge.className = "px-2.5 py-1 text-xs font-semibold uppercase tracking-wider rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30";
        badge.innerText = "ARMED & READY";
        icon.className = "fa-solid fa-shield-check";
        iconContainer.className = "p-3 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-2xl";
    }

    // Update Country Chart
    if (countryChart && stats.top_countries) {
        countryChart.data.labels = stats.top_countries.map(c => c.country);
        countryChart.data.datasets[0].data = stats.top_countries.map(c => c.count);
        countryChart.update();
    }

    // Update Password Chart
    if (passwordChart && stats.top_passwords) {
        passwordChart.data.labels = stats.top_passwords.map(p => p.password);
        passwordChart.data.datasets[0].data = stats.top_passwords.map(p => p.count);
        passwordChart.update();
    }
}

function updateAttacksTable(attacks) {
    const tbody = document.getElementById("attackFeedBody");
    tbody.innerHTML = "";

    if (!attacks || attacks.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="py-4 text-center text-slate-500">No attack activity detected yet.</td></tr>`;
        return;
    }

    attacks.slice(0, 15).forEach(att => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-slate-800/40 transition";

        let badge = "";
        let payload = "";

        if (att.eventid === "cowrie.login.failed") {
            badge = `<span class="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 text-[10px]">Failed Login</span>`;
            payload = `<span class="text-slate-400">User:</span> <strong class="text-slate-200">${escapeHtml(att.username || "")}</strong>` + (att.password ? ` / <span class="text-slate-400">Pass:</span> <strong class="text-amber-300">${escapeHtml(att.password)}</strong>` : ` <span class="text-slate-500 text-[10px]">(Password Redacted)</span>`);
        } else if (att.eventid === "cowrie.login.success") {
            badge = `<span class="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px]">Lured In</span>`;
            payload = `<span class="text-emerald-400 font-semibold">Trapped Shell:</span> <strong class="text-slate-100">${att.username || ""}</strong>`;
        } else if (att.eventid === "cowrie.command.input") {
            badge = `<span class="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px]">Command</span>`;
            payload = `<span class="text-emerald-300 font-mono">$ ${escapeHtml(att.input || "")}</span>`;
        } else {
            badge = `<span class="px-2 py-0.5 rounded bg-slate-500/10 text-slate-400 border border-slate-500/20 text-[10px]">Connect</span>`;
            payload = `Port ${att.dst_port || 22}`;
        }

        const dateStr = att.timestamp ? att.timestamp.replace("T", " ").substring(0, 19) : "";

        tr.innerHTML = `
            <td class="py-2.5 text-slate-400">${dateStr}</td>
            <td class="py-2.5 text-cyan-300 font-mono font-medium">${att.src_ip || "Unknown"}</td>
            <td class="py-2.5 text-slate-300"><i class="fa-solid fa-earth-americas text-slate-500 mr-1.5"></i>${att.country || "Proxy"}</td>
            <td class="py-2.5">${badge}</td>
            <td class="py-2.5 truncate max-w-xs">${payload}</td>
        `;
        tbody.appendChild(tr);
    });
}

function updateTerminalStream(commands) {
    const feed = document.getElementById("terminalCommandsFeed");
    if (!commands || commands.length === 0) {
        return;
    }

    feed.innerHTML = "";
    commands.forEach(cmd => {
        const item = document.createElement("div");
        item.className = "p-2 rounded bg-slate-900 border border-slate-800/80 hover:border-slate-700 transition";
        const dateStr = cmd.timestamp ? cmd.timestamp.split("T")[1].substring(0, 8) : "";
        item.innerHTML = `
            <div class="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                <span>[${dateStr}] IP: ${cmd.src_ip} (${cmd.country || "Proxy"})</span>
                <span class="text-amber-500">session:${cmd.session || "ssh"}</span>
            </div>
            <div class="text-emerald-400 text-xs font-mono break-all">
                <span class="text-slate-600 select-none">root@srv-prod-db01:~# </span>${escapeHtml(cmd.input || "")}
            </div>
        `;
        feed.appendChild(item);
    });
}

async function triggerSimulatedAttack(type) {
    try {
        const res = await fetch("/api/simulate-attack", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ type: type })
        });
        const data = await res.json();
        pollData();
    } catch (e) {
        alert("Simulation error: " + e);
    }
}

async function triggerSelfHealing() {
    try {
        const res = await fetch("/api/trigger-healing", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();
        if (data.recovery_status === "HEALING_FAILED" || data.status === "error") {
            alert("Self-Healing FAILED: Honeypot service could not be verified on Port 2222.\nForensic evidence was preserved.");
        } else {
            alert(`Self-Healing Completed (${data.recovery_status})!\n- Forensic evidence archived with SHA-256 integrity\n- Honeypot service verified active on Port 2222\n- Action: ${data.action || "HEALED"}`);
        }
        pollData();
    } catch (e) {
        alert("Healing trigger error: " + e);
    }
}

function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function updateAlerts(alerts) {
    const list = document.getElementById("alertsList");
    const count = document.getElementById("alertCount");
    if (!list) return;
    count.innerText = alerts.length + " alert" + (alerts.length !== 1 ? "s" : "");
    if (alerts.length === 0) {
        list.innerHTML = '<p class="text-slate-500 italic">No alerts detected yet. Run 3+ SSH login attempts to trigger detection.</p>';
        return;
    }
    list.innerHTML = "";
    alerts.forEach(a => {
        const div = document.createElement("div");
        div.className = "flex flex-wrap items-center gap-3 p-2.5 rounded-lg bg-red-950/30 border border-red-800/40";
        div.innerHTML = `
            <i class="fa-solid fa-triangle-exclamation text-red-400"></i>
            <span class="text-red-300 font-bold">${escapeHtml(a.ip || "")}</span>
            <span class="text-slate-400">${a.failed_attempts} failed attempts</span>
            <span class="text-slate-500">•</span>
            <span class="text-slate-400">${escapeHtml(a.detected_at || "")}</span>
            <span class="ml-auto text-amber-400 text-[11px]">${escapeHtml(a.message || "")}</span>
        `;
        list.appendChild(div);
    });
}
