# Run against the local Compose stack. Uses a temporary Neo4j transaction to hold the environment lock.
$ErrorActionPreference = 'Stop'
$neo4j = 'http://127.0.0.1:7474/db/neo4j/tx'
$api = 'http://127.0.0.1:8080/api/v1'
$basic = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('neo4j:attackgraph-local-only'))
$headers = @{ Authorization = "Basic $basic" }
$lockBody = @{ statements = @(@{ statement = "MERGE (l:EnvironmentLock {environment_id:'northstar'}) SET l.version=coalesce(l.version,0)+1 RETURN l.version" }) } | ConvertTo-Json -Depth 5

function Assert-WaitsForGraphLock($url, $method, $body) {
    $tx = Invoke-RestMethod -Method Post -Uri $neo4j -Headers $headers -ContentType application/json -Body $lockBody
    if ($tx.errors.Count -ne 0 -or -not $tx.commit) { throw 'Could not acquire Neo4j environment lock' }
    $txURL = $tx.commit -replace '/commit$', ''
    $job = $null
    try {
        $job = Start-Job -ArgumentList $url,$method,$body,$api -ScriptBlock {
            param($url,$method,$body,$api)
            $ErrorActionPreference = 'Stop'
            $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            Invoke-RestMethod -Method Post -Uri "$api/auth/login" -WebSession $session -ContentType application/json -Body '{"email":"analyst@northstar.local","password":"northstar-demo-local"}' | Out-Null
            'ready'
            $request = @{Uri=$url;Method=$method;WebSession=$session}
            if ($body) { $request.ContentType='application/json'; $request.Body=$body }
            Invoke-RestMethod @request | Out-Null
            'complete'
        }
        $ready = $false
        for ($i=0; $i -lt 30; $i++) {
            if (@(Receive-Job $job -Keep) -contains 'ready') { $ready = $true; break }
            if ($job.State -ne 'Running') { throw 'API request finished before reaching lock check' }
            Start-Sleep -Milliseconds 100
        }
        if (-not $ready) { throw 'API request did not sign in' }
        Start-Sleep -Milliseconds 500
        if ($job.State -ne 'Running') { throw 'API write did not wait for the environment lock' }
    } finally {
        Invoke-RestMethod -Method Delete -Uri $txURL -Headers $headers | Out-Null
    }
    if (-not (Wait-Job $job -Timeout 15)) { Stop-Job $job; throw 'API request did not resume after lock release' }
    $output = @(Receive-Job $job -ErrorAction Stop)
    Remove-Job $job
    if ($output -notcontains 'complete') { throw 'API request failed after lock release' }
}

Assert-WaitsForGraphLock "$api/environments/northstar/vulnerabilities/AG-001/state" 'Patch' '{"state":"active"}'
Assert-WaitsForGraphLock "$api/environments/northstar/snapshots" 'Post' $null
'Graph edits and snapshot capture waited for the environment lock.'
