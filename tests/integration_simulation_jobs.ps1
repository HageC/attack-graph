$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:8080/api/v1'
$editor = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$viewer = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$harbor = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $editor -ContentType application/json -Body '{"email":"analyst@northstar.local","password":"northstar-demo-local"}' | Out-Null
try {
    $snapshot = Invoke-RestMethod -Uri "$base/environments/northstar/snapshots" -Method Post -WebSession $editor
    $body = @{snapshot_id=$snapshot.id;start_asset_id='ws-01';target_asset_id='id-01';seed=42;duration_seconds=300;max_steps=12;initial_capabilities=@('foothold');detection_coverage=1;control_effectiveness=0} | ConvertTo-Json -Compress
    $run = Invoke-RestMethod -Uri "$base/environments/northstar/simulations" -Method Post -WebSession $editor -ContentType application/json -Body $body
    $job = Invoke-RestMethod -Uri "$base/environments/northstar/simulations/$($run.id)/jobs" -Method Post -WebSession $editor
    $paused = Invoke-RestMethod -Uri "$base/environments/northstar/simulation-jobs/$($job.id)/pause" -Method Post -WebSession $editor
    if ($paused.status -ne 'paused') { throw 'Pause did not persist' }
    Start-Sleep -Milliseconds 900
    $stillPaused = Invoke-RestMethod -Uri "$base/environments/northstar/simulation-jobs/$($job.id)" -WebSession $editor
    if ($stillPaused.status -ne 'paused' -or $stillPaused.event_cursor -ne $paused.event_cursor) { throw 'Paused job advanced' }
    docker compose restart api | Out-Null
    $ready = $false
    for ($attempt=0; $attempt -lt 30; $attempt++) {
        try { $health = Invoke-RestMethod -Uri "$base/health" -TimeoutSec 2; if ($health.status -eq 'ok') { $ready = $true; break } } catch {}
        Start-Sleep -Milliseconds 300
    }
    if (-not $ready) { throw 'API did not recover after restart' }
    $afterRestart = Invoke-RestMethod -Uri "$base/environments/northstar/simulation-jobs/$($job.id)" -WebSession $editor
    if ($afterRestart.status -ne 'paused' -or $afterRestart.event_cursor -ne $paused.event_cursor) { throw 'Job state did not survive API restart' }
    $speed = Invoke-RestMethod -Uri "$base/environments/northstar/simulation-jobs/$($job.id)/speed" -Method Post -WebSession $editor -ContentType application/json -Body '{"speed":4}'
    if ($speed.speed -ne 4) { throw 'Speed change failed' }
    $resumed = Invoke-RestMethod -Uri "$base/environments/northstar/simulation-jobs/$($job.id)/resume" -Method Post -WebSession $editor
    if ($resumed.status -ne 'running') { throw 'Resume did not persist' }
    $final = $resumed
    for ($i=0; $i -lt 30 -and $final.status -ne 'completed'; $i++) {
        Start-Sleep -Milliseconds 200
        $final = Invoke-RestMethod -Uri "$base/environments/northstar/simulation-jobs/$($job.id)" -WebSession $editor
    }
    if ($final.status -ne 'completed' -or $final.event_cursor -ne $final.total_events -or $final.events.Count -ne $run.events.Count) { throw 'Job did not deliver all events' }
    $stoppedJob = Invoke-RestMethod -Uri "$base/environments/northstar/simulations/$($run.id)/jobs" -Method Post -WebSession $editor
    $stopped = Invoke-RestMethod -Uri "$base/environments/northstar/simulation-jobs/$($stoppedJob.id)/stop" -Method Post -WebSession $editor
    if ($stopped.status -ne 'stopped') { throw 'Stop did not persist' }
    try { Invoke-RestMethod -Uri "$base/environments/northstar/simulation-jobs/$($stoppedJob.id)/resume" -Method Post -WebSession $editor | Out-Null; throw 'Stopped job resumed' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 409) { throw } }
    Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $viewer -ContentType application/json -Body '{"email":"viewer@northstar.local","password":"northstar-viewer-local"}' | Out-Null
    try { Invoke-RestMethod -Uri "$base/environments/northstar/simulation-jobs/$($job.id)/stop" -Method Post -WebSession $viewer | Out-Null; throw 'Viewer changed job' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw } }
    Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $harbor -ContentType application/json -Body '{"email":"analyst@harbor.local","password":"harbor-demo-local"}' | Out-Null
    try { Invoke-RestMethod -Uri "$base/environments/northstar/simulation-jobs/$($job.id)" -WebSession $harbor | Out-Null; throw 'Cross-tenant job read succeeded' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw } }
    'Simulation job state, cursor, cancellation, and access checks passed.'
} finally {
    foreach ($item in @($editor,$viewer,$harbor)) { try { Invoke-RestMethod -Uri "$base/auth/logout" -Method Post -WebSession $item | Out-Null } catch {} }
}
