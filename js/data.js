/**
 * Threat Intelligence Dataset & Security Knowledge Base - Upgraded Enterprise Edition
 * Includes Geo-Locations for Attack Map, 14-Tactic MITRE ATT&CK Matrix, & STIX 2.1 Templates
 */

const THREAT_DATA = {
  // Global Attack Map Geographic Nodes (Latitude & Longitude on Canvas Projection)
  geoNodes: {
    "US-EAST": { name: "Washington DC, USA", x: 260, y: 190, region: "North America", type: "Target/Origin" },
    "US-WEST": { name: "Silicon Valley, USA", x: 180, y: 195, region: "North America", type: "Target" },
    "EU-WEST": { name: "London, UK", x: 470, y: 155, region: "Europe", type: "Target/Origin" },
    "EU-CENTRAL": { name: "Frankfurt, Germany", x: 505, y: 150, region: "Europe", type: "Target" },
    "RU-MOSCOW": { name: "Moscow, Russia", x: 580, y: 135, region: "Eurasia", type: "Origin" },
    "CN-BEIJING": { name: "Beijing, China", x: 770, y: 195, region: "Asia Pacific", type: "Origin" },
    "KP-PYONGYANG": { name: "Pyongyang, North Korea", x: 810, y: 200, region: "Asia Pacific", type: "Origin" },
    "JP-TOKYO": { name: "Tokyo, Japan", x: 835, y: 205, region: "Asia Pacific", type: "Target" },
    "SG-SINGAPORE": { name: "Singapore", x: 755, y: 290, region: "SE Asia", type: "Target" },
    "AU-SYDNEY": { name: "Sydney, Australia", x: 860, y: 360, region: "Oceania", type: "Target" },
    "BR-SAOPAULO": { name: "São Paulo, Brazil", x: 340, y: 330, region: "South America", type: "Target/Origin" }
  },

  // Active Attack Stream Trajectories for Canvas Visualizer
  attackTrajectories: [
    { origin: "RU-MOSCOW", target: "US-EAST", vector: "XZ-Backdoor SSH Exploit", severity: "CRITICAL", color: "#ff0055" },
    { origin: "CN-BEIJING", target: "US-WEST", vector: "Volt Typhoon LotL Proxy", severity: "CRITICAL", color: "#ff0055" },
    { origin: "KP-PYONGYANG", target: "SG-SINGAPORE", vector: "Lazarus Crypto Bridge Drain", severity: "HIGH", color: "#ff9900" },
    { origin: "RU-MOSCOW", target: "EU-CENTRAL", vector: "LockBit 3.0 Ransomware Drop", severity: "HIGH", color: "#ff9900" },
    { origin: "EU-WEST", target: "BR-SAOPAULO", vector: "Phishing AiTM OAuth Proxy", severity: "MEDIUM", color: "#ffcc00" },
    { origin: "CN-BEIJING", target: "AU-SYDNEY", vector: "Kubernetes Unauth API Hijack", severity: "HIGH", color: "#ff9900" }
  ],

  // Full 14-Tactic MITRE ATT&CK Matrix Data
  mitreMatrix: [
    {
      tacticId: "TA0001",
      tacticName: "Initial Access",
      coverage: "88%",
      techniques: [
        { id: "T1190", name: "Exploit Public-Facing App", status: "HIGH RISK", actor: "APT29" },
        { id: "T1566", name: "Phishing Lures", status: "ACTIVE", actor: "Lazarus" },
        { id: "T1195", name: "Supply Chain Compromise", status: "CRITICAL", actor: "APT29" }
      ]
    },
    {
      tacticId: "TA0002",
      tacticName: "Execution",
      coverage: "92%",
      techniques: [
        { id: "T1059", name: "Command & Scripting Interpreter", status: "HIGH RISK", actor: "Volt Typhoon" },
        { id: "T1204", name: "User Execution", status: "ACTIVE", actor: "LockBit" }
      ]
    },
    {
      tacticId: "TA0003",
      tacticName: "Persistence",
      coverage: "84%",
      techniques: [
        { id: "T1078", name: "Valid Accounts", status: "CRITICAL", actor: "APT29" },
        { id: "T1543", name: "Create or Modify System Process", status: "MONITORED", actor: "UNC4841" }
      ]
    },
    {
      tacticId: "TA0004",
      tacticName: "Privilege Escalation",
      coverage: "80%",
      techniques: [
        { id: "T1068", name: "Exploitation for Privilege Escalation", status: "CRITICAL", actor: "APT29" },
        { id: "T1548", name: "Abuse Elevation Control", status: "ACTIVE", actor: "LockBit" }
      ]
    },
    {
      tacticId: "TA0005",
      tacticName: "Defense Evasion",
      coverage: "76%",
      techniques: [
        { id: "T1036", name: "Masquerading", status: "HIGH RISK", actor: "Volt Typhoon" },
        { id: "T1027", name: "Obfuscated Files or Information", status: "CRITICAL", actor: "Lazarus" }
      ]
    },
    {
      tacticId: "TA0006",
      tacticName: "Credential Access",
      coverage: "85%",
      techniques: [
        { id: "T1003", name: "OS Credential Dumping", status: "CRITICAL", actor: "LockBit" },
        { id: "T1556", name: "Modify Authentication Process", status: "ACTIVE", actor: "APT29" }
      ]
    },
    {
      tacticId: "TA0007",
      tacticName: "Discovery",
      coverage: "90%",
      techniques: [
        { id: "T1082", name: "System Information Discovery", status: "ACTIVE", actor: "Volt Typhoon" },
        { id: "T1046", name: "Network Service Discovery", status: "MONITORED", actor: "Botnets" }
      ]
    },
    {
      tacticId: "TA0008",
      tacticName: "Lateral Movement",
      coverage: "78%",
      techniques: [
        { id: "T1021", name: "Remote Services (RDP/SSH)", status: "HIGH RISK", actor: "LockBit" },
        { id: "T1570", name: "Lateral Tool Transfer", status: "ACTIVE", actor: "APT29" }
      ]
    },
    {
      tacticId: "TA0009",
      tacticName: "Collection",
      coverage: "82%",
      techniques: [
        { id: "T1005", name: "Data from Local System", status: "ACTIVE", actor: "Lazarus" },
        { id: "T1114", name: "Email Collection", status: "CRITICAL", actor: "APT29" }
      ]
    },
    {
      tacticId: "TA0011",
      tacticName: "Command and Control",
      coverage: "89%",
      techniques: [
        { id: "T1572", name: "Protocol Tunneling", status: "CRITICAL", actor: "Volt Typhoon" },
        { id: "T1071", name: "Application Layer Protocol", status: "ACTIVE", actor: "LockBit" }
      ]
    },
    {
      tacticId: "TA0010",
      tacticName: "Exfiltration",
      coverage: "86%",
      techniques: [
        { id: "T1048", name: "Exfiltration Over Alternative Protocol", status: "HIGH RISK", actor: "Lazarus" },
        { id: "T1567", name: "Exfiltration to Cloud Storage", status: "CRITICAL", actor: "APT29" }
      ]
    },
    {
      tacticId: "TA0040",
      tacticName: "Impact",
      coverage: "94%",
      techniques: [
        { id: "T1486", name: "Data Encrypted for Impact", status: "CRITICAL", actor: "LockBit" },
        { id: "T1490", name: "Inhibit System Recovery", status: "CRITICAL", actor: "LockBit" }
      ]
    }
  ],

  // Automated Ingestion Telemetry Simulator Templates
  telemetryTemplates: [
    {
      title: "CISA Alert: Active Exploitation of Palo Alto PAN-OS (CVE-2024-3400)",
      severity: "CRITICAL",
      category: "Zero-Day / RCE",
      source: "CISA KEV Feed",
      targetIndustry: "Defense, Healthcare, Finance",
      threatActor: "UTG-Q-002",
      description: "Command injection vulnerability in PAN-OS GlobalProtect feature allows unauthenticated attacker to execute arbitrary code with root privileges.",
      iocs: ["172.56.21.90", "malicious-pan-update.com", "a8f9c7e6d5b4a3f2e1"],
      mitigation: "Apply PAN-OS hotfix 10.2.9-h1 or disable telemetry collection temporarily."
    },
    {
      title: "Dark Web Leak: 15.2M Stolen OAuth Refresh Tokens Offered for Sale",
      severity: "HIGH",
      category: "Credential Theft",
      source: "Dark Web Monitor",
      targetIndustry: "Cloud SaaS, Tech Enterprise",
      threatActor: "Combed Syndicate",
      description: "Stolen session cookies and refresh tokens harvested from infected info-stealer malware endpoints globally.",
      iocs: ["session-token-dump.onion", "185.190.140.22"],
      mitigation: "Revoke all active enterprise user refresh tokens and enforce periodic re-authentication."
    },
    {
      title: "AbuseIPDB Flagged: 8,500 IP SSH Brute-Force Botnet Surge",
      severity: "MEDIUM",
      category: "Botnet Activity",
      source: "AbuseIPDB",
      targetIndustry: "Web Hosting, Infrastructure",
      threatActor: "Mirai Variant",
      description: "Coordinated port 22 credential stuffing targeting default root/admin passwords on Linux cloud instances.",
      iocs: ["193.142.146.210", "45.83.223.14"],
      mitigation: "Enable fail2ban or drop inbound SSH connections not originating from authorized bastion CIDRs."
    }
  ],

  // Threat Feed Alerts (Base Feed)
  threatAlerts: [
    {
      id: "ALT-2026-9081",
      title: "Active XZ Utils Backdoor Variant Detected in Linux Repositories",
      severity: "CRITICAL",
      category: "Supply Chain / Zero-Day",
      source: "CISA KEV Feed",
      sourceIcon: "shield-alert",
      timestamp: "2026-07-29 08:45:12",
      targetIndustry: "Cloud Service Providers, Government, Defense",
      threatActor: "APT29 (Cozy Bear)",
      status: "NEW",
      description: "Sophisticated malicious payload injection targeting sshd authentication via liblzma. Allows unauthenticated remote code execution with root privileges.",
      iocs: ["185.220.101.45", "70529d47970d473458c679a9539265f2", "malicious-xz-mirror.ru"],
      mitigation: "Downgrade xz-utils to version 5.4.x immediately or deploy memory integrity protection rules."
    },
    {
      id: "ALT-2026-8942",
      title: "LockBit 3.0 Ransomware Campaign Targeting Financial Institutions",
      severity: "HIGH",
      category: "Ransomware",
      source: "AlienVault OTX",
      sourceIcon: "skull",
      timestamp: "2026-07-29 07:12:00",
      targetIndustry: "Financial Services, Banking, FinTech",
      threatActor: "LockBit Supp",
      status: "INVESTIGATING",
      description: "Phishing lures containing weaponized ISO files extracting Group Policy Object passwords to spread ransomware domain-wide within 3 hours.",
      iocs: ["45.142.214.98", "finance-update-auth.com", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
      mitigation: "Block external ISO mount capabilities via Windows GPO; isolate compromised AD Domain Controllers."
    },
    {
      id: "ALT-2026-8711",
      title: "Volt Typhoon Zero-Day Exploitation of Edge Networking Routers",
      severity: "CRITICAL",
      category: "APT / Nation-State",
      source: "AbuseIPDB",
      sourceIcon: "globe",
      timestamp: "2026-07-28 22:30:15",
      targetIndustry: "Critical Infrastructure, Telecom, Energy",
      threatActor: "Volt Typhoon",
      status: "INVESTIGATING",
      description: "Living-off-the-land (LotL) tactics targeting SOHO routers to establish persistent encrypted proxies into critical grid networks.",
      iocs: ["194.165.16.89", "185.244.25.10", "c2.volt-infra.net"],
      mitigation: "Enforce multi-factor authentication on all administrative web interfaces; rotate SSH host keys."
    },
    {
      id: "ALT-2026-8504",
      title: "Massive Spear-Phishing Surge Impersonating Microsoft 365 OAuth Apps",
      severity: "MEDIUM",
      category: "Phishing / Credential Theft",
      source: "Dark Web Monitor",
      sourceIcon: "mail",
      timestamp: "2026-07-28 18:05:40",
      targetIndustry: "Healthcare, Higher Education, Legal",
      threatActor: "Lazarus Group (Sub-group)",
      status: "MITIGATED",
      description: "Adversary-in-the-Middle (AiTM) phishing proxies bypassing standard FIDO2 authentication via malicious consent grants.",
      iocs: ["login.microsoft-auth-verify.xyz", "103.145.22.14"],
      mitigation: "Revoke unverified OAuth app consent privileges and enforce Conditional Access App Control policies."
    },
    {
      id: "ALT-2026-8199",
      title: "Kubernetes API Server Unauthenticated Access Vulnerability",
      severity: "HIGH",
      category: "Cloud Security",
      source: "NIST NVD Database",
      sourceIcon: "server",
      timestamp: "2026-07-27 14:18:22",
      targetIndustry: "SaaS, E-Commerce, Logistics",
      threatActor: "Unknown Botnet Syndicate",
      status: "NEW",
      description: "Misconfigured RBAC permissions permitting anonymous users to spawn privileged pods for crypto-mining and data exfiltration.",
      iocs: ["k8s-pod-miner.pool.org", "193.201.224.5"],
      mitigation: "Disable `--anonymous-auth` on control plane nodes; implement NetworkPolicies restricting API server access."
    }
  ],

  // Vulnerabilities Base Database
  vulnerabilities: [
    {
      cveId: "CVE-2024-3094",
      title: "XZ Utils LZMA Decompressor Backdoor",
      cvssScore: 10.0,
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      epssScore: 0.974,
      cisaKev: true,
      status: "ACTIVE EXPLOIT",
      affectedVendor: "Tukaani / Open Source",
      affectedProduct: "xz-utils 5.6.0 & 5.6.1",
      publishDate: "2024-03-29",
      attackVector: "Network (Unauthenticated)",
      description: "Malicious code added to xz tarballs during build process that intercepts RSA public key decryption in OpenSSH daemon.",
      patchUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
      remediation: "Downgrade xz-utils package to 5.4.6 or rebuild OpenSSH against clean liblzma."
    },
    {
      cveId: "CVE-2024-21626",
      title: "runC Container Breakout Vulnerability (leaky vessels)",
      cvssScore: 8.6,
      cvssVector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      epssScore: 0.882,
      cisaKev: true,
      status: "PATCH AVAILABLE",
      affectedVendor: "Open Container Initiative",
      affectedProduct: "runc <= 1.1.11",
      publishDate: "2024-01-31",
      attackVector: "Local / Container Guest",
      description: "Process file descriptor leak allowing malicious container image to gain host filesystem write access.",
      patchUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
      remediation: "Upgrade runc to version 1.1.12+ across all Kubernetes nodes and Docker engines."
    },
    {
      cveId: "CVE-2024-1709",
      title: "ConnectWise ScreenConnect Authentication Bypass",
      cvssScore: 10.0,
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      epssScore: 0.968,
      cisaKev: true,
      status: "ACTIVE EXPLOIT",
      affectedVendor: "ConnectWise",
      affectedProduct: "ScreenConnect 23.9.7 and prior",
      publishDate: "2024-02-19",
      attackVector: "Network",
      description: "Authentication bypass allowing an unauthenticated user to create administrative accounts on ScreenConnect servers.",
      patchUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-1709",
      remediation: "Upgrade on-premise ScreenConnect servers to version 23.9.8 immediately."
    },
    {
      cveId: "CVE-2023-4863",
      title: "WebP Heap Buffer Overflow in Google Chrome & libwebp",
      cvssScore: 8.8,
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
      epssScore: 0.941,
      cisaKev: true,
      status: "PATCHED",
      affectedVendor: "Google / libwebp",
      affectedProduct: "Chrome < 116.0.5845.187, libwebp < 1.3.2",
      publishDate: "2023-09-12",
      attackVector: "Remote (Web Browsing)",
      description: "Heap buffer overflow in WebP image processing library triggerable via specially crafted WebP image files.",
      patchUrl: "https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
      remediation: "Deploy auto-updates for browsers, Electron apps, and operating system image rendering libs."
    }
  ],

  // Threat Actors Base Data
  threatActors: [
    {
      id: "TA-01",
      name: "APT29 (Cozy Bear / Midnight Blizzard)",
      origin: "Russia (SVR Foreign Intelligence)",
      motivation: "Espionage, Intelligence Gathering",
      targetedSectors: "Government, Defense, IT Supply Chain, Think Tanks",
      confidence: "HIGH",
      mitreTactics: ["T1078 - Valid Accounts", "T1195 - Supply Chain Compromise", "T1566 - Phishing", "T1055 - Process Injection"],
      associatedIOCs: ["185.220.101.45", "solorigate-c2.com", "malicious-xz-mirror.ru"],
      keyMalware: ["Sunburst", "FoggyWeb", "EnvyScout", "CosmicDuke"],
      activeCampaigns: "SolarWinds Supply Chain, M365 Password Spraying, XZ Utils Compromise"
    },
    {
      id: "TA-02",
      name: "Lazarus Group (HIDDEN COBRA)",
      origin: "North Korea (RGB State Sponsors)",
      motivation: "Financial Theft, Cryptocurrency Heists, Sabotage",
      targetedSectors: "Crypto Exchanges, Defense, Healthcare, Financial Networks",
      confidence: "HIGH",
      mitreTactics: ["T1566.002 - Spearphishing Link", "T1059.003 - Windows Command Shell", "T1486 - Data Encrypted for Impact"],
      associatedIOCs: ["103.145.22.14", "pay-lazarus.onion", "crypto-steal-drop.org"],
      keyMalware: ["WannaCry", "AppleJeus", "TraderTraitor", "FastCash"],
      activeCampaigns: "Axie Infinity Bridge Drain, Weaponized PDF Lures, SWIFT Bank Transfer Fraud"
    },
    {
      id: "TA-03",
      name: "LockBit Ransomware Syndicate",
      origin: "Cybercrime Affiliate Network (RaaS)",
      motivation: "Financial Extortion",
      targetedSectors: "Healthcare, Manufacturing, Law Enforcement, Enterprise Software",
      confidence: "HIGH",
      mitreTactics: ["T1490 - Inhibit System Recovery", "T1003 - OS Credential Dumping", "T1021 - Remote Services"],
      associatedIOCs: ["45.142.214.98", "lockbitapt.onion", "finance-update-auth.com"],
      keyMalware: ["LockBit 2.0", "LockBit 3.0 (Black)", "StealBit Exfiltrator"],
      activeCampaigns: "Boeing Data Leak, NHS Healthcare Network Hijack, Fulton County Breach"
    },
    {
      id: "TA-04",
      name: "Volt Typhoon (BRONZE SILHOUETTE)",
      origin: "China (PLA State-Sponsored)",
      motivation: "Pre-Positioning for Critical Infrastructure Sabotage",
      targetedSectors: "Telecommunications, Ports, Energy Grids, Transportation",
      confidence: "HIGH",
      mitreTactics: ["T1078.003 - Local Accounts", "T1036 - Masquerading", "T1572 - Protocol Tunneling"],
      associatedIOCs: ["194.165.16.89", "185.244.25.10", "c2.volt-infra.net"],
      keyMalware: ["KV-Botnet", "FastReverseProxy", "Living-off-the-Land Scripts"],
      activeCampaigns: "Guam Infrastructure Infiltration, US Pacific Port Command Access"
    }
  ],

  // IOC Base Database
  iocs: [
    { type: "IPv4", value: "185.220.101.45", threatType: "C2 Server", confidenceScore: 98, firstSeen: "2026-07-20", lastSeen: "2026-07-29", status: "ACTIVE", country: "RU", malwareFamily: "XZ-Backdoor" },
    { type: "IPv4", value: "45.142.214.98", threatType: "Ransomware Drop Node", confidenceScore: 92, firstSeen: "2026-07-21", lastSeen: "2026-07-29", status: "ACTIVE", country: "NL", malwareFamily: "LockBit 3.0" },
    { type: "Domain", value: "finance-update-auth.com", threatType: "Phishing Proxy", confidenceScore: 95, firstSeen: "2026-07-18", lastSeen: "2026-07-28", status: "BLOCKED", country: "US", malwareFamily: "AiTM Proxy" },
    { type: "SHA256", value: "70529d47970d473458c679a9539265f2a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", threatType: "Trojan Payload", confidenceScore: 100, firstSeen: "2026-07-29", lastSeen: "2026-07-29", status: "ACTIVE", country: "GLOBAL", malwareFamily: "Liblzma Injector" },
    { type: "IPv4", value: "194.165.16.89", threatType: "Botnet Node", confidenceScore: 89, firstSeen: "2026-07-15", lastSeen: "2026-07-28", status: "MONITORED", country: "CN", malwareFamily: "KV-Proxy" }
  ],

  // Data Sources (Deliverable 3)
  dataSources: [
    {
      id: "DS-01",
      name: "CISA Known Exploited Vulnerabilities (KEV)",
      type: "Government Cyber Agency Feed",
      updateFrequency: "Real-time / Hourly",
      reliabilityScore: "99.9%",
      format: "JSON REST API",
      totalRecords: "1,140 Verified Exploits",
      schema: "{ cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate }",
      apiEndpoint: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      description: "Authoritative list of vulnerabilities that have been actively exploited in the wild, mandated for federal patch remediation."
    },
    {
      id: "DS-02",
      name: "AlienVault Open Threat Exchange (OTX)",
      type: "Crowdsourced Threat Intelligence Platform",
      updateFrequency: "Every 15 Minutes",
      reliabilityScore: "94.5%",
      format: "STIX 2.1 / TAXII / JSON",
      totalRecords: "12.4M Pulse Indicators",
      schema: "{ pulse_id, name, author_name, created, indicators: [{ indicator, type, title }] }",
      apiEndpoint: "https://otx.alienvault.com/api/v1/pulses/subscribed",
      description: "Community-driven threat intelligence feed containing pulse indicators, malicious file hashes, and IP reputation scores."
    },
    {
      id: "DS-03",
      name: "AbuseIPDB Threat Intelligence API",
      type: "IP Reputation & Abuse Tracking",
      updateFrequency: "Near Real-Time",
      reliabilityScore: "96.2%",
      format: "REST JSON API",
      totalRecords: "4.8M Flagged IPs",
      schema: "{ ipAddress, abuseConfidenceScore, countryCode, totalReports, lastReportedAt, categories }",
      apiEndpoint: "https://api.abuseipdb.com/api/v2/check",
      description: "Global IP abuse reporter tracking port scanners, DDoS bots, SSH brute force engines, and spam relays."
    }
  ],

  // Recommendations (Deliverable 4)
  securityRecommendations: [
    {
      id: "REC-01",
      priority: "CRITICAL",
      title: "Mandate Emergency Patching for CISA KEV Listed CVEs",
      category: "Vulnerability Management",
      description: "Enforce a strict 72-hour SLA for remediating all CVEs flagged on CISA's Known Exploited Vulnerabilities catalog.",
      effort: "Medium",
      impact: "High (Reduces breach likelihood by 78%)",
      mitreRef: "M1051 - Update Software"
    },
    {
      id: "REC-02",
      priority: "CRITICAL",
      title: "Enforce Hardened FIDO2/WebAuthn Hardware MFA",
      category: "Identity & Access Control",
      description: "Phase out legacy SMS/Push TOTP in favor of phishing-resistant FIDO2 security keys to eliminate AiTM credential theft.",
      effort: "High",
      impact: "High (Stops 99.9% of automated account takeovers)",
      mitreRef: "M1032 - Multi-factor Authentication"
    }
  ],

  // Slide Deck Data (Deliverable 5)
  presentationSlides: [
    {
      slideNum: 1,
      title: "Centralized Cybersecurity Threat Intelligence Platform",
      subtitle: "Proactive Threat Monitoring & Executive Risk Management",
      presenter: "Cybersecurity Engineering Team",
      content: "An end-to-end framework designed to aggregate multi-source threat intelligence, quantify organizational risk exposure, and accelerate incident response.",
      highlights: [
        "Aggregation of 4+ Threat Intelligence Feeds (CISA KEV, AlienVault OTX, AbuseIPDB, NVD)",
        "Real-Time Risk Posture Scoring Engine & Canvas Global Attack Visualizer",
        "Automated IOC Extraction & 14-Tactic MITRE ATT&CK Mapping",
        "STIX 2.1 JSON, CSV, & PDF Deliverables Exporter Suite"
      ]
    },
    {
      slideNum: 2,
      title: "Problem Statement & Business Relevance",
      subtitle: "The Complexity of Emerging Cyber Threats",
      presenter: "Cybersecurity Engineering Team",
      content: "Modern organizations face fragmented threat signals, rapid zero-day exploitation windows, and sophisticated APT adversaries.",
      highlights: [
        "Information Overload: Security teams monitor 10+ disjointed threat tools daily",
        "Exploitation Velocity: Vulnerabilities like CVE-2024-3094 are weaponized in hours",
        "Business Impact: Average cost of a data breach reaches $4.45M without proactive intel",
        "Solution Value: Centralized dashboard reduces mean-time-to-detect (MTTD) by 64%"
      ]
    },
    {
      slideNum: 3,
      title: "Global Attack Canvas & Live Telemetry Architecture",
      subtitle: "Multi-Source Feed Processing & Real-Time Visualization",
      presenter: "Cybersecurity Engineering Team",
      content: "Real-time attack map projection engine combined with live telemetry stream simulator.",
      highlights: [
        "Interactive 2D World Projection canvas rendering attack trajectories",
        "Background Telemetry Ingestion Simulator with sound triggers & status triage",
        "NIST CSF 2.0 Risk Calculator for organizational compliance evaluation",
        "STIX 2.1 standard format compatibility for threat intelligence sharing"
      ]
    }
  ]
};
