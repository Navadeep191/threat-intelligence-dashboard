/**
 * Cybersecurity Threat Intelligence REST API & SSE Server
 * Port: 5000 | Native Node.js HTTP Architecture
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = 5000;
const DB_FILE = path.join(__dirname, 'data', 'threat_database.json');

// SSE Connected Client Connections
let sseClients = [];

// Helper: Read Database
function readDB() {
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error("Error reading database file:", err);
    return { threatAlerts: [], vulnerabilities: [], threatActors: [], iocs: [] };
  }
}

// Helper: Write Database
function saveDB(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error("Error writing to database file:", err);
  }
}

// Helper: Send JSON Response
function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(JSON.stringify(data));
}

// Background Simulated Ingestion Generator
setInterval(() => {
  if (sseClients.length === 0) return;

  const db = readDB();
  const sampleTitles = [
    "CISA Alert: Palo Alto PAN-OS Zero-Day (CVE-2024-3400) Exploitation",
    "Dark Web Leak: 18.5M OAuth Refresh Tokens Offered on Russian Forum",
    "Mirai Botnet Surge: 12,000 IPs Target Cloud SSH Endpoints",
    "Ivanti EPMM RCE Vulnerability Active Sweep Detected"
  ];
  const title = sampleTitles[Math.floor(Math.random() * sampleTitles.length)];

  const newAlert = {
    id: `ALT-2026-${Math.floor(1000 + Math.random() * 9000)}`,
    title: title,
    severity: Math.random() > 0.4 ? "CRITICAL" : "HIGH",
    category: "Real-Time Ingestion",
    source: "CISA KEV Live Stream",
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    targetIndustry: "Cloud, Defense, Finance",
    threatActor: "APT-Syndicate",
    status: "NEW",
    description: "Automated live ingestion alert pushed by backend server telemetry engine.",
    iocs: [`185.220.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`, "c2-ingest-stream.net"],
    mitigation: "Deploy urgent SOC mitigation rule and isolate affected CIDR block."
  };

  db.threatAlerts.unshift(newAlert);
  if (db.threatAlerts.length > 25) db.threatAlerts.pop();
  saveDB(db);

  // Broadcast to SSE clients
  sseClients.forEach(client => {
    client.write(`data: ${JSON.stringify({ type: 'NEW_ALERT', alert: newAlert })}\n\n`);
  });
}, 10000);

// HTTP Request Listener
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // Handle CORS Preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    res.end();
    return;
  }

  // 1. Health Endpoint
  if (pathname === '/api/health' && method === 'GET') {
    const db = readDB();
    return sendJSON(res, 200, {
      status: "ONLINE",
      version: "2.1.0-Enterprise",
      databaseRecords: {
        threatAlerts: db.threatAlerts.length,
        vulnerabilities: db.vulnerabilities.length,
        threatActors: db.threatActors.length,
        iocs: db.iocs.length
      },
      activeSseClients: sseClients.length,
      uptime: process.uptime()
    });
  }

  // 2. Threat Alerts GET
  if (pathname === '/api/threats' && method === 'GET') {
    const db = readDB();
    let alerts = db.threatAlerts;
    const severity = parsedUrl.query.severity;
    if (severity && severity !== 'ALL') {
      alerts = alerts.filter(a => a.severity === severity);
    }
    return sendJSON(res, 200, alerts);
  }

  // 3. Threat Alert Status PATCH (/api/threats/:id/status)
  if (pathname.startsWith('/api/threats/') && pathname.endsWith('/status') && method === 'PATCH') {
    const id = pathname.split('/')[3];
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const payload = JSON.parse(body);
        const db = readDB();
        const alert = db.threatAlerts.find(a => a.id === id);
        if (alert) {
          alert.status = payload.status;
          saveDB(db);
          return sendJSON(res, 200, { success: true, alert });
        } else {
          return sendJSON(res, 404, { error: "Alert not found" });
        }
      } catch (e) {
        return sendJSON(res, 400, { error: "Invalid JSON payload" });
      }
    });
    return;
  }

  // 4. Vulnerabilities CVE GET
  if (pathname === '/api/cve' && method === 'GET') {
    const db = readDB();
    return sendJSON(res, 200, db.vulnerabilities);
  }

  // 5. Threat Actors GET
  if (pathname === '/api/actors' && method === 'GET') {
    const db = readDB();
    return sendJSON(res, 200, db.threatActors);
  }

  // 6. IOC Database GET
  if (pathname === '/api/iocs' && method === 'GET') {
    const db = readDB();
    return sendJSON(res, 200, db.iocs);
  }

  // 7. STIX 2.1 Dynamic Generator GET
  if (pathname === '/api/stix' && method === 'GET') {
    const db = readDB();
    const stixBundle = {
      type: "bundle",
      id: `bundle--${Math.floor(Math.random() * 1000000)}`,
      spec_version: "2.1",
      objects: db.iocs.map(ioc => ({
        type: ioc.type === "Domain" ? "domain-name" : "ipv4-addr",
        id: `indicator--${Math.floor(Math.random() * 100000)}`,
        created: new Date().toISOString(),
        modified: new Date().toISOString(),
        name: ioc.threatType,
        value: ioc.value,
        confidence: ioc.confidenceScore,
        labels: [ioc.malwareFamily.toLowerCase(), "threat-intel-backend"]
      }))
    };
    return sendJSON(res, 200, stixBundle);
  }

  // 8. Server-Sent Events (SSE) Live Telemetry Stream
  if (pathname === '/api/telemetry/stream' && method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });

    res.write(`data: ${JSON.stringify({ type: 'CONNECTED', message: 'Connected to SOC Backend Live Telemetry Stream' })}\n\n`);
    sseClients.push(res);

    req.on('close', () => {
      sseClients = sseClients.filter(client => client !== res);
    });
    return;
  }

  // 404 Fallback
  return sendJSON(res, 404, { error: "Endpoint not found" });
});

// Launch Server
server.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🛡️ Threat Intelligence REST API Backend Server Running`);
  console.log(`📍 Endpoint: http://localhost:${PORT}/api/health`);
  console.log(`📡 SSE Stream: http://localhost:${PORT}/api/telemetry/stream`);
  console.log(`=======================================================`);
});
