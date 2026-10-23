# Run against a local Docker Compose stack. Creates synthetic records and removes them.
$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:8080/api/v1'
$assetID = 'ws-02'
$targetID = 'db-02'
$vulnerabilityID = $null
$relationshipID = $null
$transitionID = $null
$originalPosition = $null

$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    try {
        $health = Invoke-RestMethod "$base/health"
        if ($health.status -eq 'ok') { $ready = $true; break }
    } catch { Start-Sleep -Seconds 2 }
}
if (-not $ready) { throw 'Go API did not become healthy within 60 seconds' }

try {
    Invoke-RestMethod "$base/environments/northstar/graph" | Out-Null
    throw 'Unauthenticated graph access unexpectedly succeeded'
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw }
}
try {
    Invoke-RestMethod -Method Post -Uri "$base/auth/login" -ContentType application/json -Body '{"email":"analyst@northstar.local","password":"wrong-password"}' | Out-Null
    throw 'Invalid password unexpectedly succeeded'
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw }
}
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod -Method Post -Uri "$base/auth/login" -WebSession $session -ContentType application/json -Body '{"email":"analyst@northstar.local","password":"northstar-demo-local"}' | Out-Null
$PSDefaultParameterValues['Invoke-RestMethod:WebSession'] = $session
$PSDefaultParameterValues['Invoke-RestMethod:Headers'] = @{ Origin = 'http://127.0.0.1:8080' }
if ((Invoke-RestMethod "$base/environments").Count -ne 1) { throw 'Northstar account listed another tenant' }
$auditBefore = [int](docker compose exec -T postgres psql -U attackgraph -d attackgraph -Atc 'SELECT count(*) FROM audit_records')
try {
    Invoke-RestMethod -Method Post -Uri "$base/environments/northstar/relationships" -Headers @{Origin='https://unrelated.example'} -ContentType application/json -Body '{"source":"ws-01","target":"db-01","kind":"CAN_REACH"}' | Out-Null
    throw 'Cross-origin write unexpectedly succeeded'
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw }
}
$session.Headers.Remove('Origin') | Out-Null

$harborSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod -Method Post -Uri "$base/auth/login" -WebSession $harborSession -ContentType application/json -Body '{"email":"analyst@harbor.local","password":"harbor-demo-local"}' | Out-Null
if ((Invoke-RestMethod "$base/environments" -WebSession $harborSession)[0].id -ne 'harbor') { throw 'Harbor account listed another tenant' }
try {
    Invoke-RestMethod "$base/environments/northstar/graph" -WebSession $harborSession | Out-Null
    throw 'Cross-tenant graph access unexpectedly succeeded'
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw }
}
try {
    Invoke-RestMethod -Method Post -Uri "$base/environments/northstar/relationships" -WebSession $harborSession -ContentType application/json -Body '{"source":"ws-01","target":"db-01","kind":"CAN_REACH"}' | Out-Null
    throw 'Cross-tenant relationship write unexpectedly succeeded'
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw }
}
$viewerSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod -Method Post -Uri "$base/auth/login" -WebSession $viewerSession -ContentType application/json -Body '{"email":"viewer@northstar.local","password":"northstar-viewer-local"}' | Out-Null
if ((Invoke-RestMethod "$base/environments/northstar/graph" -WebSession $viewerSession).assets.Count -lt 1) { throw 'Viewer could not read assigned environment' }
try {
    Invoke-RestMethod -Method Patch -Uri "$base/environments/northstar/assets/ws-02/position" -WebSession $viewerSession -ContentType application/json -Body '{"x":80,"y":380}' | Out-Null
    throw 'Viewer write unexpectedly succeeded'
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw }
}

function Analyze {
    $body = @{ environment_id = 'northstar'; start_asset_id = $assetID; target_asset_id = $targetID } | ConvertTo-Json
    return Invoke-RestMethod -Method Post -Uri "$base/attack-paths/analyze" -ContentType application/json -Body $body
}
function Expect-Unprocessable($url, $body) {
    try {
        Invoke-RestMethod -Method Post -Uri $url -ContentType application/json -Body ($body | ConvertTo-Json) | Out-Null
        throw "Expected 422 from $url"
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 422) { throw }
    }
}

try {
    if ((Analyze).paths.Count -ne 0) { throw 'Expected no path before creating model relationships' }
    $asset = (Invoke-RestMethod "$base/environments/northstar/graph").assets | Where-Object id -eq $assetID
    $originalPosition = @{ x = $asset.x; y = $asset.y }
    $moved = @{ x = [int]$asset.x + 40; y = [int]$asset.y + 20 }
    Invoke-RestMethod -Method Patch -Uri "$base/environments/northstar/assets/$assetID/position" -ContentType application/json -Body ($moved | ConvertTo-Json) | Out-Null
    docker compose restart api | Out-Null
    $afterRestart = $null
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $afterRestart = (Invoke-RestMethod "$base/environments/northstar/graph").assets | Where-Object id -eq $assetID
            if ($afterRestart) { break }
        } catch { Start-Sleep -Seconds 2 }
    }
    if ($afterRestart.x -ne $moved.x -or $afterRestart.y -ne $moved.y) { throw 'Saved graph position did not survive restart' }
    $v = Invoke-RestMethod -Method Post -Uri "$base/environments/northstar/vulnerabilities" -ContentType application/json -Body (@{ asset_id = $assetID; title = 'Integration test weakness'; description = 'Synthetic test only'; severity = 'low'; cvss = 2.5; mitigation = 'Remove test record' } | ConvertTo-Json)
    $vulnerabilityID = $v.id
    $transition = @{ source = $assetID; target = $targetID; reason = 'Synthetic modeled permission gap'; likelihood = 0.42; required_capability = 'foothold'; grants_capability = 'data_access'; required_relationship = 'CAN_REACH'; vulnerability_id = $vulnerabilityID }
    Expect-Unprocessable "$base/environments/northstar/transitions" $transition
    $rel = Invoke-RestMethod -Method Post -Uri "$base/environments/northstar/relationships" -ContentType application/json -Body (@{source=$assetID;target=$targetID;kind='CAN_REACH'} | ConvertTo-Json)
    $relationshipID = $rel.id
    if ((Analyze).paths.Count -ne 0) { throw 'Topology alone produced an attack path' }
    $t = Invoke-RestMethod -Method Post -Uri "$base/environments/northstar/transitions" -ContentType application/json -Body ($transition | ConvertTo-Json)
    $transitionID = $t.id
    if ((Analyze).paths.Count -ne 1) { throw 'Expected modeled transition to create one path' }
    Invoke-RestMethod -Method Patch -Uri "$base/environments/northstar/transitions/$transitionID" -ContentType application/json -Body '{"blocked":true}' | Out-Null
    if ((Analyze).paths.Count -ne 0) { throw 'Blocked transition still produced a path' }
    $auditAfter = [int](docker compose exec -T postgres psql -U attackgraph -d attackgraph -Atc 'SELECT count(*) FROM audit_records')
    if ($auditAfter -le $auditBefore) { throw 'Successful mutation did not create an audit record' }
    Write-Output 'Relationship integration workflow passed.'
} finally {
    foreach ($item in @($vulnerabilityID,$relationshipID,$transitionID)) {
        if ($item -and $item -notmatch '^(AG|rel|tr)-[a-f0-9]{24}$') { throw "Unexpected generated ID: $item" }
    }
    if ($transitionID) { docker compose exec -T neo4j cypher-shell -u neo4j -p attackgraph-local-only "MATCH ()-[r:TRANSITION {id:'$transitionID'}]->() DELETE r" | Out-Null }
    if ($relationshipID) { docker compose exec -T neo4j cypher-shell -u neo4j -p attackgraph-local-only "MATCH ()-[r:CAN_REACH {id:'$relationshipID'}]->() DELETE r" | Out-Null }
    if ($vulnerabilityID) { docker compose exec -T neo4j cypher-shell -u neo4j -p attackgraph-local-only "MATCH (v:Vulnerability {id:'$vulnerabilityID'}) DETACH DELETE v" | Out-Null }
    if ($originalPosition) { Invoke-RestMethod -Method Patch -Uri "$base/environments/northstar/assets/$assetID/position" -ContentType application/json -Body ($originalPosition | ConvertTo-Json) | Out-Null }
    foreach ($authSession in @($session,$harborSession,$viewerSession)) {
        Invoke-RestMethod -Method Post -Uri "$base/auth/logout" -WebSession $authSession | Out-Null
    }
}
