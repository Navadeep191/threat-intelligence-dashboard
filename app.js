/**
 * Threat Intelligence Dashboard - Core Application Engine (Full-Stack Production Edition)
 * Live Render Backend API: https://threat-intelligence-dashboard-l2wv.onrender.com/api
 */

// Global Audio Context & Sound Alert Synthesizer
let audioCtx = null;

function getAudioContext() {
  if (!audioCtx) {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (AudioContextClass) audioCtx = new AudioContextClass();
  }
  if (audioCtx && audioCtx.state === "suspended") {
    audioCtx.resume();
  }
  return audioCtx;
}

window.playAlertBeep = function(isCritical = false) {
  try {
    const ctx = getAudioContext();
    if (!ctx) return;

    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = isCritical ? "sawtooth" : "sine";
    osc.frequency.setValueAtTime(isCritical ? 1200 : 880, ctx.currentTime);
    if (isCritical) {
      osc.frequency.exponentialRampToValueAtTime(600, ctx.currentTime + 0.3);
    }

    gain.gain.setValueAtTime(0.15, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + (isCritical ? 0.35 : 0.2));

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start();
    osc.stop(ctx.currentTime + (isCritical ? 0.35 : 0.2));
  } catch (e) {
    console.warn("Audio synthesis error:", e);
  }
};

// Global Simulator Handlers
window.toggleTelemetrySim = function() {
  if (!window.appState) return;
  window.appState.simActive = !window.appState.simActive;

  const btn = document.getElementById("btn-toggle-sim");
  if (btn) {
    btn.classList.toggle("active", window.appState.simActive);
    btn.innerHTML = window.appState.simActive ? `<i data-lucide="pause"></i> LIVE INGESTION` : `<i data-lucide="play"></i> PAUSED`;
    if (typeof lucide !== "undefined") lucide.createIcons();
  }

  showToast(window.appState.simActive ? "Live Telemetry Ingestion: RESUMED" : "Live Telemetry Ingestion: PAUSED");
};

window.toggleSimAudio = function() {
  if (!window.appState) return;
  window.appState.simAudio = !window.appState.simAudio;

  if (window.appState.simAudio) {
    getAudioContext();
    window.playAlertBeep(false);
  }

  const btn = document.getElementById("btn-toggle-audio");
  if (btn) {
    btn.classList.toggle("active", window.appState.simAudio);
    btn.innerHTML = window.appState.simAudio ? `<i data-lucide="volume-2"></i> SOUND ON` : `<i data-lucide="volume-x"></i> SOUND OFF`;
    if (typeof lucide !== "undefined") lucide.createIcons();
  }

  showToast(window.appState.simAudio ? "SOC Audio Alerts: ENABLED 🔊" : "SOC Audio Alerts: MUTED 🔇");
};

window.simulateAptAttack = function(actorId) {
  if (!window.appState) return;
  getAudioContext();

  const actor = window.appState.threatActors.find(a => a.id === actorId) || THREAT_DATA.threatActors.find(a => a.id === actorId);
  if (!actor) return;

  const newAlert = {
    id: `ALT-2026-${Math.floor(1000 + Math.random() * 9000)}`,
    title: `CRITICAL APT CAMPAIGN: ${actor.name} Launched Active Exploitation Phase`,
    severity: "CRITICAL",
    category: "Nation-State APT Campaign",
    source: "SOC Telemetry Simulator",
    timestamp: new Date().toISOString().replace("T", " ").substring(0, 19),
    targetIndustry: actor.targetedSectors,
    threatActor: actor.name,
    status: "NEW",
    description: `Targeted exploitation campaign using malware family [${actor.keyMalware.join(", ")}]. Mapped tactics: ${actor.mitreTactics.join(", ")}.`,
    iocs: actor.associatedIOCs,
    mitigation: "Deploy urgent EDR isolation rules and block associated C2 IP addresses immediately."
  };

  window.appState.alerts.unshift(newAlert);
  if (window.appState.alerts.length > 25) window.appState.alerts.pop();

  if (window.appState.simAudio) window.playAlertBeep(true);

  if (window.updateDashboardMetrics) window.updateDashboardMetrics();
  if (window.renderAlertsList) window.renderAlertsList();

  showToast(`🚨 SIMULATED ATTACK: ${actor.name} launched active campaign!`);
};

// Global CVE Detail Modal Functions
window.viewCveDetail = function(cveId) {
  let cve = null;
  if (window.appState && window.appState.vulnerabilities) {
    cve = window.appState.vulnerabilities.find(v => v.cveId === cveId);
  }
  if (!cve && typeof THREAT_DATA !== "undefined" && THREAT_DATA.vulnerabilities) {
    cve = THREAT_DATA.vulnerabilities.find(v => v.cveId === cveId);
  }
  if (!cve) return;

  const modal = document.getElementById("cve-modal-overlay");
  if (!modal) return;

  const setEl = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setEl("modal-cve-id", cve.cveId);
  setEl("modal-cve-title", cve.title);

  const cvssEl = document.getElementById("modal-cvss-score");
  if (cvssEl) {
    cvssEl.textContent = `${cve.cvssScore} / 10`;
    cvssEl.className = `badge ${cve.cvssScore >= 9.0 ? 'badge-critical' : 'badge-high'}`;
  }

  setEl("modal-epss-score", `${(cve.epssScore * 100).toFixed(1)}%`);

  const kevEl = document.getElementById("modal-cisa-kev");
  if (kevEl) {
    kevEl.textContent = cve.cisaKev ? "CISA KEV LISTED" : "NOT LISTED";
    kevEl.className = `badge ${cve.cisaKev ? 'badge-critical' : 'badge-low'}`;
  }

  setEl("modal-exploit-status", cve.status);
  setEl("modal-vendor", cve.affectedVendor || "N/A");
  setEl("modal-product", cve.affectedProduct || "N/A");
  setEl("modal-attack-vector", cve.attackVector || "Network");
  setEl("modal-publish-date", cve.publishDate || "N/A");

  setEl("modal-cvss-vector", cve.cvssVector || "N/A");
  setEl("modal-description", cve.description || "No detailed description available.");
  setEl("modal-remediation", cve.remediation || "Deploy vendor security update immediately.");

  const patchUrlEl = document.getElementById("modal-patch-url");
  if (patchUrlEl) patchUrlEl.href = cve.patchUrl || `https://nvd.nist.gov/vuln/detail/${cve.cveId}`;

  modal.classList.add("active");
  if (typeof lucide !== "undefined") lucide.createIcons();
};

window.closeCveModal = function() {
  const modal = document.getElementById("cve-modal-overlay");
  if (modal) modal.classList.remove("active");
};

// Application Controller Initialization
document.addEventListener("DOMContentLoaded", () => {
  // Live Render Production API Endpoint (with fallback to local)
  const PRIMARY_API = "https://threat-intelligence-dashboard-l2wv.onrender.com/api";
  const LOCAL_API = "http://localhost:5000/api";

  const state = {
    alerts: [...THREAT_DATA.threatAlerts],
    vulnerabilities: [...THREAT_DATA.vulnerabilities],
    threatActors: [...THREAT_DATA.threatActors],
    iocs: [...THREAT_DATA.iocs],
    activeTab: "overview",
    currentSlide: 0,
    charts: {},
    simActive: true,
    simAudio: true,
    backendConnected: false,
    activeApiBase: PRIMARY_API,
    simInterval: null,
    animFrame: null
  };

  window.appState = state;

  // Initialize Core Systems
  initClock();
  initNavigation();
  checkBackendHealth();
  initMetrics();
  initCharts();
  renderAlertsList();
  renderVulnerabilitiesTable();
  renderThreatActorsGrid();
  renderIOCsTable();
  renderDataSourcesList();
  renderRecommendationsList();
  renderSlideView();
  renderMitreMatrix();
  initAttackMapCanvas();
  recalculateCompliance();

  setupFilterListeners();
  setupReportExportListeners();

  startTelemetryIngestionLoop();

  window.updateDashboardMetrics = initMetrics;
  window.renderAlertsList = renderAlertsList;

  function startTelemetryIngestionLoop() {
    if (state.simInterval) clearInterval(state.simInterval);

    state.simInterval = setInterval(() => {
      if (!state.simActive) return;

      const template = THREAT_DATA.telemetryTemplates[Math.floor(Math.random() * THREAT_DATA.telemetryTemplates.length)];
      const newAlert = {
        ...template,
        id: `ALT-2026-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date().toISOString().replace("T", " ").substring(0, 19),
        status: "NEW"
      };

      state.alerts.unshift(newAlert);
      if (state.alerts.length > 25) state.alerts.pop();

      initMetrics();
      renderAlertsList();

      if (state.simAudio) window.playAlertBeep(newAlert.severity === "CRITICAL");
      showToast(`⚡ TELEMETRY INGESTION: ${newAlert.title.substring(0, 42)}...`);
    }, 8000);
  }

  async function checkBackendHealth() {
    const badgeText = document.getElementById("backend-status-text");
    try {
      // Test Live Render Production Endpoint First
      let res = await fetch(`${PRIMARY_API}/health`);
      if (res.ok) {
        state.activeApiBase = PRIMARY_API;
        state.backendConnected = true;
        if (badgeText) {
          badgeText.textContent = `CONNECTED TO LIVE RENDER REST BACKEND`;
          badgeText.style.color = "var(--green-low)";
        }
        fetchBackendData();
        return;
      }

      // Fallback to Local Host
      res = await fetch(`${LOCAL_API}/health`);
      if (res.ok) {
        state.activeApiBase = LOCAL_API;
        state.backendConnected = true;
        if (badgeText) {
          badgeText.textContent = `CONNECTED TO LOCAL REST BACKEND: :5000`;
          badgeText.style.color = "var(--green-low)";
        }
        fetchBackendData();
        return;
      }
    } catch (e) {
      state.backendConnected = false;
      if (badgeText) {
        badgeText.textContent = `OFFLINE MODE (CLIENT STORAGE)`;
        badgeText.style.color = "var(--orange-high)";
      }
    }
  }

  async function fetchBackendData() {
    try {
      const [threatsRes, cveRes, actorsRes, iocRes] = await Promise.all([
        fetch(`${state.activeApiBase}/threats`),
        fetch(`${state.activeApiBase}/cve`),
        fetch(`${state.activeApiBase}/actors`),
        fetch(`${state.activeApiBase}/iocs`)
      ]);

      if (threatsRes.ok) state.alerts = await threatsRes.json();
      if (cveRes.ok) state.vulnerabilities = await cveRes.json();
      if (actorsRes.ok) state.threatActors = await actorsRes.json();
      if (iocRes.ok) state.iocs = await iocRes.json();

      initMetrics();
      renderAlertsList();
      renderVulnerabilitiesTable();
      renderThreatActorsGrid();
      renderIOCsTable();
    } catch (err) {
      console.warn("Backend fetch error:", err);
    }
  }

  function initClock() {
    const clockEl = document.getElementById("live-clock");
    const updateTime = () => {
      const now = new Date();
      if (clockEl) {
        clockEl.textContent = now.toISOString().replace("T", " ").substring(0, 19) + " UTC";
      }
    };
    updateTime();
    setInterval(updateTime, 1000);
  }

  function initNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    const tabPanes = document.querySelectorAll(".tab-pane");

    navItems.forEach(item => {
      item.addEventListener("click", () => {
        const targetTab = item.getAttribute("data-tab");
        navItems.forEach(n => n.classList.remove("active"));
        item.classList.add("active");

        tabPanes.forEach(pane => {
          if (pane.id === `tab-${targetTab}`) {
            pane.classList.add("active");
          } else {
            pane.classList.remove("active");
          }
        });

        state.activeTab = targetTab;

        if (targetTab === "overview" && state.charts.categoryChart) {
          setTimeout(() => {
            state.charts.categoryChart.resize();
            state.charts.trendChart.resize();
          }, 100);
        }

        if (targetTab === "attack-map") {
          setTimeout(initAttackMapCanvas, 100);
        }
      });
    });
  }

  function initMetrics() {
    const criticalAlerts = state.alerts.filter(a => a.severity === "CRITICAL" && a.status !== "MITIGATED").length;
    const activeCVEs = state.vulnerabilities.filter(v => v.status === "ACTIVE EXPLOIT").length;
    const activeActors = state.threatActors.length;

    let riskScore = 25 + (criticalAlerts * 15) + (activeCVEs * 12);
    if (riskScore > 100) riskScore = 98;

    const riskEl = document.getElementById("metric-risk-score");
    const criticalEl = document.getElementById("metric-critical-alerts");
    const cveEl = document.getElementById("metric-active-cves");
    const actorsEl = document.getElementById("metric-active-actors");

    if (riskEl) riskEl.textContent = `${riskScore} / 100`;
    if (criticalEl) criticalEl.textContent = criticalAlerts;
    if (cveEl) cveEl.textContent = activeCVEs;
    if (actorsEl) actorsEl.textContent = activeActors;
  }

  function initCharts() {
    if (typeof Chart === "undefined") return;

    Chart.defaults.color = "#94a3b8";
    Chart.defaults.borderColor = "rgba(51, 65, 85, 0.4)";
    Chart.defaults.font.family = "'Inter', sans-serif";

    const ctxCat = document.getElementById("chartCategoryBreakdown");
    if (ctxCat) {
      const categories = {};
      state.alerts.forEach(a => {
        categories[a.category] = (categories[a.category] || 0) + 1;
      });

      state.charts.categoryChart = new Chart(ctxCat, {
        type: "doughnut",
        data: {
          labels: Object.keys(categories),
          datasets: [{
            data: Object.values(categories),
            backgroundColor: ["#ff0055", "#ff9900", "#00f3ff", "#a855f7", "#00ff66", "#3b82f6"],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: "bottom", labels: { boxWidth: 12, padding: 12 } } }
        }
      });
    }

    const ctxTrend = document.getElementById("chartThreatTrend");
    if (ctxTrend) {
      state.charts.trendChart = new Chart(ctxTrend, {
        type: "line",
        data: {
          labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Today"],
          datasets: [
            {
              label: "Critical / Zero-Day Alerts",
              data: [4, 7, 5, 12, 9, 14, state.alerts.length],
              borderColor: "#ff0055",
              backgroundColor: "rgba(255, 0, 85, 0.1)",
              fill: true,
              tension: 0.4
            },
            {
              label: "Ransomware & Phishing Lures",
              data: [12, 19, 15, 22, 28, 25, 34],
              borderColor: "#00f3ff",
              backgroundColor: "rgba(0, 243, 255, 0.05)",
              fill: true,
              tension: 0.4
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: "top" } },
          scales: {
            y: { beginAtZero: true, grid: { color: "rgba(51, 65, 85, 0.3)" } },
            x: { grid: { display: false } }
          }
        }
      });
    }
  }

  function renderAlertsList(filteredData = state.alerts) {
    const container = document.getElementById("threat-alerts-container");
    const summaryContainer = document.getElementById("threat-alerts-summary");

    if (summaryContainer) {
      summaryContainer.innerHTML = state.alerts.slice(0, 3).map(alert => renderAlertCardHTML(alert)).join("");
    }

    if (!container) return;

    if (filteredData.length === 0) {
      container.innerHTML = `<div style="text-align: center; padding: 2rem; color: var(--text-muted);">No threat alerts found matching criteria.</div>`;
      return;
    }

    container.innerHTML = filteredData.map(alert => renderAlertCardHTML(alert)).join("");
    if (typeof lucide !== "undefined") lucide.createIcons();
  }

  function renderAlertCardHTML(alert) {
    const severityClass = `badge-${alert.severity.toLowerCase()}`;
    return `
      <div class="threat-item-card severity-${alert.severity}">
        <div class="threat-header">
          <span class="threat-title">${escapeHTML(alert.title)}</span>
          <div class="badge-group">
            <span class="badge ${severityClass}">${alert.severity}</span>
            <span class="badge badge-cyan">${escapeHTML(alert.source)}</span>
          </div>
        </div>
        <p style="font-size: 0.88rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
          ${escapeHTML(alert.description)}
        </p>
        <div class="threat-meta">
          <span class="meta-item"><i data-lucide="clock"></i> ${alert.timestamp}</span>
          <span class="meta-item"><i data-lucide="building"></i> Target: ${escapeHTML(alert.targetIndustry)}</span>
          <span class="meta-item"><i data-lucide="user-x"></i> Actor: ${escapeHTML(alert.threatActor)}</span>
          <span class="meta-item"><i data-lucide="activity"></i> Status: <strong style="color: var(--cyan-primary);">${alert.status}</strong></span>
        </div>
        <div class="ioc-pills">
          ${alert.iocs.map(ioc => `<span class="ioc-pill" onclick="copyToClipboard('${ioc}')"><i data-lucide="copy"></i> ${escapeHTML(ioc)}</span>`).join("")}
        </div>
        <div style="margin-top: 0.75rem; display: flex; justify-content: space-between; align-items: center;">
          <span style="font-size: 0.75rem; color: var(--green-low);"><i data-lucide="shield-check"></i> Mitigation: ${escapeHTML(alert.mitigation)}</span>
          <select onchange="updateAlertStatus('${alert.id}', this.value)" style="background: #1e293b; color: #fff; border: 1px solid #334155; padding: 0.2rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; cursor: pointer;">
            <option value="NEW" ${alert.status === "NEW" ? "selected" : ""}>Mark: NEW</option>
            <option value="INVESTIGATING" ${alert.status === "INVESTIGATING" ? "selected" : ""}>Mark: INVESTIGATING</option>
            <option value="MITIGATED" ${alert.status === "MITIGATED" ? "selected" : ""}>Mark: MITIGATED</option>
            <option value="FALSE POSITIVE" ${alert.status === "FALSE POSITIVE" ? "selected" : ""}>Mark: FALSE POSITIVE</option>
          </select>
        </div>
      </div>
    `;
  }

  function renderVulnerabilitiesTable(filteredData = state.vulnerabilities) {
    const tbody = document.getElementById("cve-table-body");
    if (!tbody) return;

    tbody.innerHTML = filteredData.map(cve => {
      const scoreBadge = cve.cvssScore >= 9.0 ? "badge-critical" : cve.cvssScore >= 7.0 ? "badge-high" : "badge-medium";
      return `
        <tr class="cve-row" data-cve="${cve.cveId}" style="cursor: pointer;">
          <td><strong style="color: var(--cyan-primary); font-family: var(--font-code);">${cve.cveId}</strong></td>
          <td>${escapeHTML(cve.title)}</td>
          <td><span class="badge ${scoreBadge}">${cve.cvssScore}</span></td>
          <td><span style="font-family: var(--font-code); font-size: 0.8rem; color: var(--purple-accent);">${(cve.epssScore * 100).toFixed(1)}%</span></td>
          <td>${cve.cisaKev ? '<span class="badge badge-critical">KEV LISTED</span>' : '<span class="badge badge-low">NO</span>'}</td>
          <td><span class="badge badge-cyan">${cve.status}</span></td>
          <td>
            <button class="btn-primary cve-detail-btn" data-cve="${cve.cveId}" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;">
              <i data-lucide="eye"></i> Details
            </button>
          </td>
        </tr>
      `;
    }).join("");

    tbody.querySelectorAll(".cve-row").forEach(row => {
      row.addEventListener("click", () => {
        const cveId = row.getAttribute("data-cve");
        if (cveId) window.viewCveDetail(cveId);
      });
    });

    tbody.querySelectorAll(".cve-detail-btn").forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const cveId = btn.getAttribute("data-cve");
        if (cveId) window.viewCveDetail(cveId);
      });
    });

    if (typeof lucide !== "undefined") lucide.createIcons();
  }

  function renderThreatActorsGrid(filteredData = state.threatActors) {
    const container = document.getElementById("threat-actors-container");
    if (!container) return;

    container.innerHTML = filteredData.map(actor => `
      <div class="actor-card">
        <div class="actor-card-header">
          <div>
            <div class="actor-name">${escapeHTML(actor.name)}</div>
            <div class="actor-origin"><i data-lucide="globe"></i> ${escapeHTML(actor.origin)}</div>
          </div>
          <span class="badge badge-purple">${actor.confidence} CONFIDENCE</span>
        </div>
        <div style="font-size: 0.85rem; color: var(--text-secondary);">
          <strong>Motivation:</strong> ${escapeHTML(actor.motivation)}<br>
          <strong>Targets:</strong> ${escapeHTML(actor.targetedSectors)}
        </div>
        <div>
          <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.35rem;">MITRE ATT&CK Tactics:</div>
          <div class="mitre-tags">
            ${actor.mitreTactics.map(t => `<span class="mitre-tag">${escapeHTML(t)}</span>`).join("")}
          </div>
        </div>
        <div style="font-size: 0.8rem; background: rgba(15, 23, 42, 0.6); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; gap: 0.5rem;">
          <div><strong style="color: var(--cyan-primary);">Campaign:</strong> ${escapeHTML(actor.activeCampaigns)}</div>
          <button class="btn-primary" onclick="simulateAptAttack('${actor.id}')" style="padding: 0.4rem 0.85rem; font-size: 0.75rem; min-width: 135px; white-space: nowrap;">
            <i data-lucide="zap"></i> Simulate Attack
          </button>
        </div>
      </div>
    `).join("");

    if (typeof lucide !== "undefined") lucide.createIcons();
  }

  function renderMitreMatrix() {
    const container = document.getElementById("mitre-matrix-container");
    if (!container) return;

    container.innerHTML = THREAT_DATA.mitreMatrix.map(tactic => `
      <div class="mitre-column">
        <div class="mitre-col-header">
          <h4>${escapeHTML(tactic.tacticName)}</h4>
          <span>${tactic.tacticId} • Coverage ${tactic.coverage}</span>
        </div>
        ${tactic.techniques.map(tech => `
          <div class="mitre-technique-card">
            <div class="mitre-tech-id">${tech.id}</div>
            <div class="mitre-tech-name">${escapeHTML(tech.name)}</div>
            <span class="badge ${tech.status === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${tech.status}</span>
          </div>
        `).join("")}
      </div>
    `).join("");
  }

  function initAttackMapCanvas() {
    const canvas = document.getElementById("attackMapCanvas");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;

    let progress = 0;

    function renderMapFrame() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      ctx.strokeStyle = "rgba(0, 243, 255, 0.05)";
      ctx.lineWidth = 1;
      for (let x = 0; x < canvas.width; x += 40) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      for (let y = 0; y < canvas.height; y += 40) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }

      const scaleX = canvas.width / 950;
      const scaleY = canvas.height / 450;

      Object.keys(THREAT_DATA.geoNodes).forEach(key => {
        const node = THREAT_DATA.geoNodes[key];
        const nx = node.x * scaleX;
        const ny = node.y * scaleY;

        ctx.fillStyle = node.type.includes("Origin") ? "#ff0055" : "#00f3ff";
        ctx.beginPath();
        ctx.arc(nx, ny, 4, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = node.type.includes("Origin") ? "rgba(255,0,85,0.4)" : "rgba(0,243,255,0.4)";
        ctx.beginPath();
        ctx.arc(nx, ny, 8 + Math.sin(progress * 0.05) * 3, 0, Math.PI * 2);
        ctx.stroke();

        ctx.fillStyle = "#94a3b8";
        ctx.font = "10px Inter";
        ctx.fillText(node.name.split(",")[0], nx + 8, ny + 3);
      });

      THREAT_DATA.attackTrajectories.forEach((traj, idx) => {
        const src = THREAT_DATA.geoNodes[traj.origin];
        const dst = THREAT_DATA.geoNodes[traj.target];
        if (!src || !dst) return;

        const x1 = src.x * scaleX;
        const y1 = src.y * scaleY;
        const x2 = dst.x * scaleX;
        const y2 = dst.y * scaleY;

        const cx = (x1 + x2) / 2;
        const cy = Math.min(y1, y2) - 50;

        ctx.strokeStyle = traj.color || "#00f3ff";
        ctx.lineWidth = 1.5;
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.quadraticCurveTo(cx, cy, x2, y2);
        ctx.stroke();
        ctx.setLineDash([]);

        const t = ((progress * 0.015) + (idx * 0.2)) % 1;
        const px = (1 - t) * (1 - t) * x1 + 2 * (1 - t) * t * cx + t * t * x2;
        const py = (1 - t) * (1 - t) * y1 + 2 * (1 - t) * t * cy + t * t * y2;

        ctx.fillStyle = traj.color || "#00f3ff";
        ctx.beginPath();
        ctx.arc(px, py, 4, 0, Math.PI * 2);
        ctx.fill();
      });

      progress++;
      state.animFrame = requestAnimationFrame(renderMapFrame);
    }

    if (state.animFrame) cancelAnimationFrame(state.animFrame);
    renderMapFrame();
  }

  function renderIOCsTable() {
    const tbody = document.getElementById("ioc-table-body");
    if (!tbody) return;
    tbody.innerHTML = state.iocs.map(ioc => `
      <tr>
        <td><span class="badge badge-cyan">${ioc.type}</span></td>
        <td><code style="color: var(--cyan-primary); font-family: var(--font-code);">${escapeHTML(ioc.value)}</code></td>
        <td>${escapeHTML(ioc.threatType)}</td>
        <td><strong style="color: var(--green-low);">${ioc.confidenceScore}%</strong></td>
        <td>${ioc.firstSeen}</td>
        <td><span class="badge ${ioc.status === "ACTIVE" ? "badge-critical" : "badge-low"}">${ioc.status}</span></td>
      </tr>
    `).join("");
  }

  function renderDataSourcesList() {
    const container = document.getElementById("data-sources-container");
    if (!container) return;
    container.innerHTML = THREAT_DATA.dataSources.map(ds => `
      <div class="threat-item-card" style="border-left-color: var(--cyan-primary);">
        <div class="threat-header">
          <span class="threat-title">${escapeHTML(ds.name)}</span>
          <span class="badge badge-cyan">${ds.type}</span>
        </div>
        <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.5rem;">${escapeHTML(ds.description)}</p>
      </div>
    `).join("");
  }

  function renderRecommendationsList() {
    const container = document.getElementById("recommendations-container");
    if (!container) return;
    container.innerHTML = THREAT_DATA.securityRecommendations.map(rec => `
      <div class="threat-item-card" style="border-left-color: ${rec.priority === "CRITICAL" ? "var(--red-critical)" : "var(--orange-high)"};">
        <div class="threat-header">
          <span class="threat-title">${escapeHTML(rec.title)}</span>
          <div class="badge-group">
            <span class="badge ${rec.priority === "CRITICAL" ? "badge-critical" : "badge-high"}">${rec.priority}</span>
            <span class="badge badge-purple">${escapeHTML(rec.mitreRef)}</span>
          </div>
        </div>
        <p style="font-size: 0.88rem; color: var(--text-secondary); margin-bottom: 0.5rem;">${escapeHTML(rec.description)}</p>
      </div>
    `).join("");
  }

  function renderSlideView() {
    const slides = THREAT_DATA.presentationSlides;
    const slide = slides[state.currentSlide];

    const slideContent = document.getElementById("presentation-slide-content");
    const slideIndicator = document.getElementById("slide-counter");

    if (slideContent && slide) {
      slideContent.innerHTML = `
        <div class="slide-title-header">
          <h2>${escapeHTML(slide.title)}</h2>
          <h4>${escapeHTML(slide.subtitle)}</h4>
        </div>
        <p style="font-size: 1.1rem; color: var(--text-secondary); margin-bottom: 1.5rem;">${escapeHTML(slide.content)}</p>
        <div class="slide-bullet-list">
          ${slide.highlights.map(h => `
            <div class="slide-bullet-item">
              <i data-lucide="shield-check" style="color: var(--cyan-primary);"></i>
              <span>${escapeHTML(h)}</span>
            </div>
          `).join("")}
        </div>
      `;
    }

    if (slideIndicator) {
      slideIndicator.textContent = `Slide ${state.currentSlide + 1} of ${slides.length}`;
    }
  }

  window.nextSlide = function() {
    if (state.currentSlide < THREAT_DATA.presentationSlides.length - 1) {
      state.currentSlide++;
      renderSlideView();
      if (typeof lucide !== "undefined") lucide.createIcons();
    }
  };

  window.prevSlide = function() {
    if (state.currentSlide > 0) {
      state.currentSlide--;
      renderSlideView();
      if (typeof lucide !== "undefined") lucide.createIcons();
    }
  };

  function setupFilterListeners() {
    const alertSearchInput = document.getElementById("alert-search-input");
    const alertSeverityFilter = document.getElementById("alert-severity-filter");

    const filterAlerts = () => {
      const query = alertSearchInput ? alertSearchInput.value.toLowerCase() : "";
      const severity = alertSeverityFilter ? alertSeverityFilter.value : "ALL";

      const filtered = state.alerts.filter(a => {
        const matchesQuery = a.title.toLowerCase().includes(query) || 
                             a.description.toLowerCase().includes(query) ||
                             a.targetIndustry.toLowerCase().includes(query) ||
                             a.iocs.some(i => i.toLowerCase().includes(query));
        const matchesSeverity = severity === "ALL" || a.severity === severity;
        return matchesQuery && matchesSeverity;
      });

      renderAlertsList(filtered);
    };

    if (alertSearchInput) alertSearchInput.addEventListener("input", filterAlerts);
    if (alertSeverityFilter) alertSeverityFilter.addEventListener("change", filterAlerts);

    const cveSearchInput = document.getElementById("cve-search-input");
    if (cveSearchInput) {
      cveSearchInput.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase();
        const filtered = state.vulnerabilities.filter(v => 
          v.cveId.toLowerCase().includes(query) ||
          v.title.toLowerCase().includes(query) ||
          v.affectedVendor.toLowerCase().includes(query) ||
          v.affectedProduct.toLowerCase().includes(query)
        );
        renderVulnerabilitiesTable(filtered);
      });
    }
  }

  window.updateAlertStatus = async function(alertId, newStatus) {
    const alert = state.alerts.find(a => a.id === alertId);
    if (alert) {
      alert.status = newStatus;
      initMetrics();

      if (state.backendConnected) {
        try {
          await fetch(`${state.activeApiBase}/threats/${alertId}/status`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus })
          });
        } catch (e) {}
      }

      showToast(`Alert ${alertId} status updated to ${newStatus}`);
    }
  };

  function setupReportExportListeners() {
    const printBtn = document.getElementById("btn-export-pdf");
    if (printBtn) {
      printBtn.addEventListener("click", () => {
        window.print();
      });
    }
  }

  window.copyToClipboard = function(text) {
    navigator.clipboard.writeText(text);
    showToast(`Copied IOC to clipboard: ${text}`);
  };

  function escapeHTML(str) {
    if (!str) return "";
    return str.replace(/[&<>'"]/g, 
      tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
  }

  function showToast(msg) {
    let toast = document.getElementById("cyber-toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.id = "cyber-toast";
      toast.style.cssText = "position: fixed; bottom: 20px; right: 20px; background: rgba(0, 243, 255, 0.95); color: #000; font-weight: 600; padding: 0.75rem 1.25rem; border-radius: 0.5rem; box-shadow: 0 0 25px rgba(0, 243, 255, 0.5); z-index: 99999; font-size: 0.85rem; transition: all 0.3s ease;";
      document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.style.opacity = "1";
    setTimeout(() => { toast.style.opacity = "0"; }, 3500);
  }
});
