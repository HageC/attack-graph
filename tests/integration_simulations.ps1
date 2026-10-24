$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:8080/api/v1'
$editor = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$viewer = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$harbor = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $editor -ContentType application/json -Body '{"email":"analyst@northstar.local","password":"northstar-demo-local"}' | Out-Null
try {
    $snapshot = Invoke-RestMethod -Uri "$base/environments/northstar/snapshots" -Method Post -WebSession $editor
    $body = @{snapshot_id=$snapshot.id;start_asset_id='ws-01';target_asset_id='id-01';seed=42;duration_seconds=300;max_steps=12;initial_capabilities=@('foothold');detection_coverage=1;control_effectiveness=0} | ConvertTo-Json -Compress
    $first = Invoke-RestMethod -Uri "$base/environments/northstar/simulations" -Method Post -WebSession $editor -ContentType application/json -Body $body
    $second = Invoke-RestMethod -Uri "$base/environments/northstar/simulations" -Method Post -WebSession $editor -ContentType application/json -Body $body
    if ($first.summary.result -ne 'target_reached' -or $first.summary.detected_attempts -ne 1) { throw 'Expected detected target arrival' }
    if ($first.events.Count -ne $second.events.Count -or $first.events[1].timestamp_seconds -ne $second.events[1].timestamp_seconds) { throw 'Seeded timeline was not reproducible' }
    $saved = Invoke-RestMethod -Uri "$base/environments/northstar/simulations/$($first.id)" -WebSession $editor
    $history = Invoke-RestMethod -Uri "$base/environments/northstar/simulations" -WebSession $editor
    if ($saved.events.Count -ne $first.events.Count -or @($history | Where-Object id -eq $first.id).Count -ne 1) { throw 'Run persistence failed' }
    Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $viewer -ContentType application/json -Body '{"email":"viewer@northstar.local","password":"northstar-viewer-local"}' | Out-Null
    try { Invoke-RestMethod -Uri "$base/environments/northstar/simulations" -Method Post -WebSession $viewer -ContentType application/json -Body $body | Out-Null; throw 'Viewer created run' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw } }
    Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $harbor -ContentType application/json -Body '{"email":"analyst@harbor.local","password":"harbor-demo-local"}' | Out-Null
    try { Invoke-RestMethod -Uri "$base/environments/northstar/simulations/$($first.id)" -WebSession $harbor | Out-Null; throw 'Cross-tenant read succeeded' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw } }
    'Simulation persistence, reproducibility, and access checks passed.'
} finally {
    foreach ($item in @($editor,$viewer,$harbor)) { try { Invoke-RestMethod -Uri "$base/auth/logout" -Method Post -WebSession $item | Out-Null } catch {} }
}
