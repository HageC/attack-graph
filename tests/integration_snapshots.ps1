# Run against the local Compose stack. Restores the seeded weakness on exit.
$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:8080/api/v1'
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$viewer = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$harbor = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod -Method Post -Uri "$base/auth/login" -WebSession $session -ContentType application/json -Body '{"email":"analyst@northstar.local","password":"northstar-demo-local"}' | Out-Null
try {
    $before = Invoke-RestMethod -Uri "$base/attack-paths/analyze" -Method Post -WebSession $session -ContentType application/json -Body '{"environment_id":"northstar","start_asset_id":"ws-01","target_asset_id":"id-01"}'
    if ($before.paths.Count -ne 1) { throw 'Expected a seeded path before mitigation' }
    $snapshot = Invoke-RestMethod -Uri "$base/environments/northstar/snapshots" -Method Post -WebSession $session
    $stored = Invoke-RestMethod -Uri "$base/environments/northstar/snapshots/$($snapshot.id)" -WebSession $session
    if ($stored.content_hash -ne $snapshot.content_hash -or $stored.vulnerabilities[0].state -ne 'active') { throw 'Snapshot contents differ from capture' }
    Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $viewer -ContentType application/json -Body '{"email":"viewer@northstar.local","password":"northstar-viewer-local"}' | Out-Null
    try {
        Invoke-RestMethod -Uri "$base/environments/northstar/snapshots" -Method Post -WebSession $viewer | Out-Null
        throw 'Viewer created a snapshot'
    } catch { if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw } }
    Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $harbor -ContentType application/json -Body '{"email":"analyst@harbor.local","password":"harbor-demo-local"}' | Out-Null
    try {
        Invoke-RestMethod -Uri "$base/environments/northstar/snapshots/$($snapshot.id)" -WebSession $harbor | Out-Null
        throw 'Cross-tenant snapshot access succeeded'
    } catch { if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw } }
    try {
        Invoke-RestMethod -Uri "$base/environments/northstar/vulnerabilities/AG-001/state" -Method Patch -WebSession $session -ContentType application/json -Body '{"state":"mitigated"}' | Out-Null
        $live = Invoke-RestMethod -Uri "$base/attack-paths/analyze" -Method Post -WebSession $session -ContentType application/json -Body '{"environment_id":"northstar","start_asset_id":"ws-01","target_asset_id":"id-01"}'
        $body = @{environment_id='northstar';snapshot_id=$snapshot.id;start_asset_id='ws-01';target_asset_id='id-01'} | ConvertTo-Json -Compress
        $replay = Invoke-RestMethod -Uri "$base/attack-paths/analyze" -Method Post -WebSession $session -ContentType application/json -Body $body
        if ($live.paths.Count -ne 0 -or $replay.paths.Count -ne 1) { throw 'Mitigation or snapshot replay returned unexpected paths' }
        $risk = Invoke-RestMethod -Uri "$base/environments/northstar/graph" -WebSession $session
        $liveWorkstation = $risk.assets | Where-Object id -eq 'ws-01'
        $savedWorkstation = $stored.graph.assets | Where-Object id -eq 'ws-01'
        if ($liveWorkstation.risk -ge $savedWorkstation.risk) { throw 'Mitigation did not lower the source risk score' }
    } finally {
        Invoke-RestMethod -Uri "$base/environments/northstar/vulnerabilities/AG-001/state" -Method Patch -WebSession $session -ContentType application/json -Body '{"state":"active"}' | Out-Null
    }
    'Vulnerability lifecycle and snapshot replay passed.'
} finally {
    foreach ($item in @($session,$viewer,$harbor)) { try { Invoke-RestMethod -Uri "$base/auth/logout" -Method Post -WebSession $item | Out-Null } catch {} }
}
