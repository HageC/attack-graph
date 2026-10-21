$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:8080/api/v1'
$editor = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$viewer = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$harbor = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $editor -ContentType application/json -Body '{"email":"analyst@northstar.local","password":"northstar-demo-local"}' | Out-Null
$rule = $null
try {
    $name = 'Integration endpoint ' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $ruleBody = @{name=$name;event_type='endpoint_alert';min_severity=1;asset_id='id-01'} | ConvertTo-Json -Compress
    $rule = Invoke-RestMethod -Uri "$base/environments/northstar/detection-rules" -Method Post -WebSession $editor -ContentType application/json -Body $ruleBody
    $snapshot = Invoke-RestMethod -Uri "$base/environments/northstar/snapshots" -Method Post -WebSession $editor
    $body = @{snapshot_id=$snapshot.id;start_asset_id='ws-01';target_asset_id='id-01';seed=42;duration_seconds=300;max_steps=12;initial_capabilities=@('foothold');detection_coverage=1;control_effectiveness=0} | ConvertTo-Json -Compress
    $run = Invoke-RestMethod -Uri "$base/environments/northstar/simulations" -Method Post -WebSession $editor -ContentType application/json -Body $body
    $job = Invoke-RestMethod -Uri "$base/environments/northstar/simulations/$($run.id)/jobs" -Method Post -WebSession $editor
    $telemetry = @()
    $alerts = @()
    for ($i=0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 200
        $telemetry = Invoke-RestMethod -Uri "$base/environments/northstar/telemetry?job_id=$($job.id)" -WebSession $editor
        $alerts = Invoke-RestMethod -Uri "$base/environments/northstar/alerts?job_id=$($job.id)" -WebSession $editor
        if ($telemetry.Count -eq $run.events.Count -and @($alerts | Where-Object rule_id -eq $rule.id).Count -eq 1) { break }
    }
    if ($telemetry.Count -ne $run.events.Count) { throw "Delivered events did not become telemetry: job $($job.id), telemetry $($telemetry.Count), run events $($run.events.Count)" }
    if (@($alerts | Where-Object rule_id -eq $rule.id).Count -ne 1) { throw 'Expected one matching endpoint alert' }
    if (@($telemetry | Where-Object { $_.schema_version -ne 1 -or $_.ground_truth -notin @('adversarial','control','scenario') }).Count -ne 0) { throw 'Telemetry schema or labels invalid' }
    $filtered = Invoke-RestMethod -Uri "$base/environments/northstar/telemetry?job_id=$($job.id)&event_type=endpoint_alert" -WebSession $editor
    if ($filtered.Count -ne 1) { throw 'Telemetry filtering failed' }
    $tested = Invoke-RestMethod -Uri "$base/environments/northstar/detection-rules/$($rule.id)/test" -Method Post -WebSession $editor -ContentType application/json -Body (@{job_id=$job.id} | ConvertTo-Json -Compress)
    if ($tested.match_count -ne 1 -or $tested.telemetry_ids.Count -ne 1) { throw 'Historical rule test failed' }
    $disabled = Invoke-RestMethod -Uri "$base/environments/northstar/detection-rules/$($rule.id)" -Method Patch -WebSession $editor -ContentType application/json -Body '{"enabled":false}'
    if ($disabled.enabled) { throw 'Rule did not disable' }
    $second = Invoke-RestMethod -Uri "$base/environments/northstar/simulations/$($run.id)/jobs" -Method Post -WebSession $editor
    for ($i=0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 200
        $secondTelemetry = Invoke-RestMethod -Uri "$base/environments/northstar/telemetry?job_id=$($second.id)" -WebSession $editor
        if ($secondTelemetry.Count -eq $run.events.Count) { break }
    }
    if ($secondTelemetry.Count -ne $run.events.Count) { throw 'Second delivery did not ingest telemetry' }
    $secondAlerts = Invoke-RestMethod -Uri "$base/environments/northstar/alerts?job_id=$($second.id)" -WebSession $editor
    if (@($secondAlerts | Where-Object rule_id -eq $rule.id).Count -ne 0) { throw 'Disabled rule created an alert' }
    docker compose restart api | Out-Null
    $ready = $false
    for ($attempt=0; $attempt -lt 30; $attempt++) {
        try { $health = Invoke-RestMethod -Uri "$base/health" -TimeoutSec 2; if ($health.status -eq 'ok') { $ready = $true; break } } catch {}
        Start-Sleep -Milliseconds 300
    }
    if (-not $ready) { throw 'API did not recover after restart' }
    $afterRestart = Invoke-RestMethod -Uri "$base/environments/northstar/telemetry?job_id=$($job.id)" -WebSession $editor
    $alertsAfterRestart = Invoke-RestMethod -Uri "$base/environments/northstar/alerts?job_id=$($job.id)" -WebSession $editor
    if ($afterRestart.Count -ne $telemetry.Count -or @($alertsAfterRestart | Where-Object rule_id -eq $rule.id).Count -ne 1) { throw 'Restart duplicated or lost telemetry or alerts' }
    Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $viewer -ContentType application/json -Body '{"email":"viewer@northstar.local","password":"northstar-viewer-local"}' | Out-Null
    try { Invoke-RestMethod -Uri "$base/environments/northstar/detection-rules" -Method Post -WebSession $viewer -ContentType application/json -Body $ruleBody | Out-Null; throw 'Viewer created rule' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw } }
    Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $harbor -ContentType application/json -Body '{"email":"analyst@harbor.local","password":"harbor-demo-local"}' | Out-Null
    try { Invoke-RestMethod -Uri "$base/environments/northstar/telemetry?job_id=$($job.id)" -WebSession $harbor | Out-Null; throw 'Cross-tenant telemetry read succeeded' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw } }
    'Telemetry ingestion, rule matching, rule testing, and access checks passed.'
} finally {
    if ($rule) { try { Invoke-RestMethod -Uri "$base/environments/northstar/detection-rules/$($rule.id)" -Method Patch -WebSession $editor -ContentType application/json -Body '{"enabled":false}' | Out-Null } catch {} }
    foreach ($item in @($editor,$viewer,$harbor)) { try { Invoke-RestMethod -Uri "$base/auth/logout" -Method Post -WebSession $item | Out-Null } catch {} }
}
