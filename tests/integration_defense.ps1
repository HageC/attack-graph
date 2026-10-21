$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:8080/api/v1'
$editor = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$viewer = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $editor -ContentType application/json -Body '{"email":"analyst@northstar.local","password":"northstar-demo-local"}' | Out-Null
try {
    $snapshot = Invoke-RestMethod -Uri "$base/environments/northstar/snapshots" -Method Post -WebSession $editor
    $config = @{snapshot_id=$snapshot.id;start_asset_id='ws-01';target_asset_id='id-01';seed=42;duration_seconds=300;max_steps=12;initial_capabilities=@('foothold');detection_coverage=0;control_effectiveness=0}
    $comparison = $config.Clone()
    $comparison.iterations = 40
    $comparison.proposed_control_effectiveness = 1
    $comparison.proposed_detection_coverage = 1
    $result = Invoke-RestMethod -Uri "$base/environments/northstar/defense/compare" -Method Post -WebSession $editor -ContentType application/json -Body ($comparison | ConvertTo-Json -Compress)
    if ($result.iterations -ne 40 -or $result.baseline.target_reached.estimate -le $result.proposed.target_reached.estimate -or $result.proposed.target_reached.estimate -ne 0) { throw 'Paired defense comparison failed' }
    $repeat = Invoke-RestMethod -Uri "$base/environments/northstar/defense/compare" -Method Post -WebSession $editor -ContentType application/json -Body ($comparison | ConvertTo-Json -Compress)
    if ($repeat.target_reached_delta.estimate -ne $result.target_reached_delta.estimate) { throw 'Seeded comparison was not reproducible' }
    $run = Invoke-RestMethod -Uri "$base/environments/northstar/simulations" -Method Post -WebSession $editor -ContentType application/json -Body ($config | ConvertTo-Json -Compress)
    $report = Invoke-RestMethod -Uri "$base/environments/northstar/reports/$($run.id)" -WebSession $editor
    if ($report.run_id -ne $run.id -or $report.snapshot_hash -ne $snapshot.content_hash -or $report.events.Count -ne $run.events.Count) { throw 'Investigation report does not match saved run' }
    $soc = Invoke-RestMethod -Uri "$base/environments/northstar/soc/summary" -WebSession $editor
    if ($soc.telemetry_events -lt 0 -or $soc.alerts -lt 0 -or $soc.events_by_type -eq $null) { throw 'SOC summary invalid' }
    Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $viewer -ContentType application/json -Body '{"email":"viewer@northstar.local","password":"northstar-viewer-local"}' | Out-Null
    try { Invoke-RestMethod -Uri "$base/environments/northstar/defense/compare" -Method Post -WebSession $viewer -ContentType application/json -Body ($comparison | ConvertTo-Json -Compress) | Out-Null; throw 'Viewer could run comparison' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw } }
    'Defense comparison, report, SOC summary, and access checks passed.'
} finally {
    foreach ($item in @($editor,$viewer)) { try { Invoke-RestMethod -Uri "$base/auth/logout" -Method Post -WebSession $item | Out-Null } catch {} }
}
