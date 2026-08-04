# 🛡️ Centralized Cybersecurity Threat Intelligence & Monitoring Dashboard

A modern, enterprise-grade Threat Intelligence Platform designed to aggregate threat feeds, security alerts, vulnerabilities (CVEs), indicators of compromise (IOCs), and threat actor profiles. Built to empower Security Operations Center (SOC) teams, risk managers, and cybersecurity analysts to proactively monitor emerging cyber threats and make informed risk management decisions.

---

## 📋 Key Features & Deliverables Included

1. **Deliverable 1: Threat Intelligence Dashboard (Interactive Web App)**
   - **Executive Overview**: Real-time risk posture score, active threat counter, critical alert indicators, and dynamic threat trend charts.
   - **Live Threat Feed Aggregator**: Filterable security feed from multiple sources (AlienVault OTX, CISA KEV, AbuseIPDB, Dark Web Monitors, MISP).
   - **Vulnerability & CVE Radar**: Searchable database of CVEs with CVSS v3/v4 scores, EPSS percentiles, CISA Known Exploited tags, affected assets, and patch recommendations.
   - **Threat Actor & IOC Directory**: Profiles of active APT groups (e.g., APT29 Cozy Bear, Lazarus Group, LockBit 3.0, Volt Typhoon) with TTPs mapped to the **MITRE ATT&CK Framework**.
   - **SOC Alert Triage Queue**: Interactive incident queue allowing analysts to update alert status (`New`, `Investigating`, `Mitigated`, `False Positive`).

2. **Deliverable 2: Threat Analysis Report**
   - Built-in report viewer and downloadable executive PDF/Markdown report covering emerging attack vectors, top targeted sectors, and active threat trends.

3. **Deliverable 3: Data Source Documentation**
   - Comprehensive taxonomy and schema docs explaining ingested data feeds, update frequencies, confidence scores, and API schemas.

4. **Deliverable 4: Security Recommendations & Hardening Guide**
   - Actionable risk mitigation strategies, patch prioritization matrix, and Zero Trust security controls.

5. **Deliverable 5: Final Presentation & Executive Deck**
   - Interactive presentation slide viewer ready for weekly mentor reviews and final evaluation.

---

## 🚀 How to Run the Application

Since this application is built using modern web standards (HTML5, CSS3, JavaScript ES6+, Chart.js, Lucide Icons), no complex server installation or build steps are required.

### Method 1: Direct File Access
Simply double-click or open `index.html` in any modern web browser (Google Chrome, Microsoft Edge, Mozilla Firefox, Safari).

### Method 2: Local HTTP Server (Optional)
If using VS Code or any terminal:
```bash
# Python 3
python -m http.server 8000
# Then open http://localhost:8000 in your browser
```

---

## 📂 Project Structure

```
threat-intelligence-dashboard/
│
├── index.html              # Main Single Page Application shell
├── css/
│   └── styles.css          # Glassmorphism dark SOC theme & responsive UI styles
├── js/
│   ├── data.js             # Comprehensive threat data, CVEs, IOCs, & actor profiles
│   └── app.js              # Application logic, charts, filtering engine, & report exporter
└── README.md               # Project overview & mentor review guide
```

---

## 🎯 Target Evaluation Alignment (60-Day Milestone)

- **Week 1 (Setup)**: Environment setup, architecture definition.
- **Week 2-3 (Research & Design)**: Data taxonomy, MITRE ATT&CK mapping, system design.
- **Week 4-6 (Development Phase 1)**: Threat aggregator, CVE database, risk posture calculator.
- **Week 7-8 (Development Phase 2)**: SOC triage, report generator, export engine.
- **Week 8-9 (Submission)**: Final documentation, presentation deck, mentor review readiness.
