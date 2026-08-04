# ==========================================================================
# Native PowerShell REST API Backend Server for Threat Intelligence Platform
# Zero External Dependencies | Built using System.Net.HttpListener
# Port: 5000 | Endpoint: http://localhost:5000/api/
# ==========================================================================

$port = 5000
$prefix = "http://localhost:$port/api/"
$dbFile = Join-Path $PSScriptRoot "data\threat_database.json"

if (-not (Test-Path $dbFile)) {
    Write-Host "Database file not found at $dbFile" -ForegroundColor Red
    exit 1
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "REST API Backend Server Running on http://localhost:5000/api/" -ForegroundColor Green
    Write-Host "=======================================================" -ForegroundColor Cyan
} catch {
    Write-Host "Error starting HttpListener: $_" -ForegroundColor Red
    exit 1
}

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response

    $response.Headers.Add("Access-Control-Allow-Origin", "*")
    $response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
    $response.Headers.Add("Access-Control-Allow-Headers", "Content-Type")

    if ($request.HttpMethod -eq "OPTIONS") {
        $response.StatusCode = 204
        $response.Close()
        continue
    }

    $rawUrl = $request.RawUrl
    $jsonContent = Get-Content $dbFile -Raw
    $response.ContentType = "application/json"
    $outString = "{}"

    # Handle API Root Index (/api/ or /api)
    if ($rawUrl -eq "/api/" -or $rawUrl -eq "/api" -or $rawUrl.Contains("/api/health")) {
        $dbObj = $jsonContent | ConvertFrom-Json
        $rootObj = @{
            service = "Cybersecurity Threat Intelligence REST API Backend"
            status = "ONLINE"
            port = $port
            records = @{
                threatAlerts = $dbObj.threatAlerts.Count
                vulnerabilities = $dbObj.vulnerabilities.Count
                threatActors = $dbObj.threatActors.Count
                iocs = $dbObj.iocs.Count
            }
            endpoints = @(
                "http://localhost:$port/api/health",
                "http://localhost:$port/api/threats",
                "http://localhost:$port/api/cve",
                "http://localhost:$port/api/actors",
                "http://localhost:$port/api/iocs",
                "http://localhost:$port/api/stix"
            )
        }
        $outString = $rootObj | ConvertTo-Json -Depth 4
        $response.StatusCode = 200
    }
    elseif ($rawUrl.Contains("/api/threats")) {
        $dbObj = $jsonContent | ConvertFrom-Json
        $outString = $dbObj.threatAlerts | ConvertTo-Json -Depth 4
        $response.StatusCode = 200
    }
    elseif ($rawUrl.Contains("/api/cve")) {
        $dbObj = $jsonContent | ConvertFrom-Json
        $outString = $dbObj.vulnerabilities | ConvertTo-Json -Depth 4
        $response.StatusCode = 200
    }
    elseif ($rawUrl.Contains("/api/actors")) {
        $dbObj = $jsonContent | ConvertFrom-Json
        $outString = $dbObj.threatActors | ConvertTo-Json -Depth 4
        $response.StatusCode = 200
    }
    elseif ($rawUrl.Contains("/api/iocs")) {
        $dbObj = $jsonContent | ConvertFrom-Json
        $outString = $dbObj.iocs | ConvertTo-Json -Depth 4
        $response.StatusCode = 200
    }
    elseif ($rawUrl.Contains("/api/stix")) {
        $dbObj = $jsonContent | ConvertFrom-Json
        $stixObj = @{
            type = "bundle"
            id = "bundle--ps-$(Get-Random)"
            spec_version = "2.1"
            objects = @(
                foreach ($i in $dbObj.iocs) {
                    @{
                        type = if ($i.type -eq "Domain") { "domain-name" } else { "ipv4-addr" }
                        id = "indicator--$(Get-Random)"
                        created = (Get-Date).ToString("o")
                        name = $i.threatType
                        value = $i.value
                        confidence = $i.confidenceScore
                    }
                }
            )
        }
        $outString = $stixObj | ConvertTo-Json -Depth 4
        $response.StatusCode = 200
    }
    else {
        $outString = '{"error":"Endpoint Not Found","availableEndpoints":["/api/health","/api/threats","/api/cve","/api/actors","/api/iocs","/api/stix"]}'
        $response.StatusCode = 404
    }

    $buffer = [System.Text.Encoding]::UTF8.GetBytes($outString)
    $response.ContentLength64 = $buffer.Length
    $response.OutputStream.Write($buffer, 0, $buffer.Length)
    $response.Close()
}
