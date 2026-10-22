# Run against the local Compose stack. Creates named layouts and deletes them afterward.
$ErrorActionPreference='Stop'
$base='http://127.0.0.1:8080/api/v1'
$admin=New-Object Microsoft.PowerShell.Commands.WebRequestSession
$viewer=New-Object Microsoft.PowerShell.Commands.WebRequestSession
$harbor=New-Object Microsoft.PowerShell.Commands.WebRequestSession
$created=@()
Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $admin -ContentType application/json -Body '{"email":"analyst@northstar.local","password":"northstar-demo-local"}' | Out-Null
try {
    $graph=Invoke-RestMethod -Uri "$base/environments/northstar/graph" -WebSession $admin
    $default=($graph.assets | Where-Object id -eq 'ws-02')
    $name="Review $([guid]::NewGuid().ToString('N').Substring(0,8))"
    $body=@{name=$name;positions=@{'ws-02'=@{x=800;y=900};'app-01'=@{x=400;y=500}}} | ConvertTo-Json -Depth 5 -Compress
    $first=Invoke-RestMethod -Uri "$base/environments/northstar/layouts" -Method Post -WebSession $admin -ContentType application/json -Body $body
    $created+= $first.id
    if ($first.positions.'ws-02'.x -ne 800) { throw 'Layout positions were not saved' }
    try { Invoke-RestMethod -Uri "$base/environments/northstar/layouts" -Method Post -WebSession $admin -ContentType application/json -Body $body | Out-Null; throw 'Duplicate layout name accepted' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 409) { throw } }
    $second=Invoke-RestMethod -Uri "$base/environments/northstar/layouts" -Method Post -WebSession $admin -ContentType application/json -Body (@{name="Alternate $name";positions=@{'ws-02'=@{x=1200;y=1300}}}|ConvertTo-Json -Depth 5 -Compress)
    $created+= $second.id
    Invoke-RestMethod -Uri "$base/environments/northstar/layouts/$($first.id)/assets/ws-02/position" -Method Patch -WebSession $admin -ContentType application/json -Body '{"x":1000,"y":1100}' | Out-Null
    docker compose restart api | Out-Null
    $ready=$false
    for ($attempt=0; $attempt -lt 30; $attempt++) { try { if ((Invoke-RestMethod -Uri "$base/health").status -eq 'ok') { $ready=$true; break } } catch { Start-Sleep -Seconds 2 } }
    if (-not $ready) { throw 'API did not restart' }
    $layouts=Invoke-RestMethod -Uri "$base/environments/northstar/layouts" -WebSession $admin
    $savedFirst=$layouts | Where-Object id -eq $first.id
    $savedSecond=$layouts | Where-Object id -eq $second.id
    if ($savedFirst.positions.'ws-02'.x -ne 1000 -or $savedSecond.positions.'ws-02'.x -ne 1200) { throw 'Named layouts did not retain separate positions' }
    $live=(Invoke-RestMethod -Uri "$base/environments/northstar/graph" -WebSession $admin).assets | Where-Object id -eq 'ws-02'
    if ($live.x -ne $default.x -or $live.y -ne $default.y) { throw 'Named layout changed default graph coordinates' }
    try { Invoke-RestMethod -Uri "$base/environments/northstar/layouts/$($first.id)/assets/no-asset/position" -Method Patch -WebSession $admin -ContentType application/json -Body '{"x":1,"y":1}' | Out-Null; throw 'Unknown asset position accepted' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw } }
    try { Invoke-RestMethod -Uri "$base/environments/northstar/layouts/$($first.id)/assets/ws-02/position" -Method Patch -WebSession $admin -ContentType application/json -Body '{"x":100001,"y":1}' | Out-Null; throw 'Out-of-bounds position accepted' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 422) { throw } }
    Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $viewer -ContentType application/json -Body '{"email":"viewer@northstar.local","password":"northstar-viewer-local"}' | Out-Null
    $visible=Invoke-RestMethod -Uri "$base/environments/northstar/layouts" -WebSession $viewer
    if ($visible.Count -lt 2) { throw 'Viewer could not read named layouts' }
    try { Invoke-RestMethod -Uri "$base/environments/northstar/layouts/$($first.id)/assets/ws-02/position" -Method Patch -WebSession $viewer -ContentType application/json -Body '{"x":1,"y":1}' | Out-Null; throw 'Viewer edited named layout' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw } }
    Invoke-RestMethod -Uri "$base/auth/login" -Method Post -WebSession $harbor -ContentType application/json -Body '{"email":"analyst@harbor.local","password":"harbor-demo-local"}' | Out-Null
    try { Invoke-RestMethod -Uri "$base/environments/northstar/layouts" -WebSession $harbor | Out-Null; throw 'Other tenant read named layouts' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw } }
    'Named layout persistence and tenant boundaries passed.'
} finally {
    foreach ($layoutID in $created) { try { Invoke-RestMethod -Uri "$base/environments/northstar/layouts/$layoutID" -Method Delete -WebSession $admin | Out-Null } catch {} }
    foreach ($session in @($admin,$viewer,$harbor)) { try { Invoke-RestMethod -Uri "$base/auth/logout" -Method Post -WebSession $session | Out-Null } catch {} }
}
