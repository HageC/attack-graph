# Run against the local Compose stack. Creates a temporary organization, then removes it.
$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:8080/api/v1'
$tag = [guid]::NewGuid().ToString('N').Substring(0,12)
$email = "admin-$tag@example.invalid"
$firstPassword = 'bootstrap-local-test-123'
$rotatedPassword = 'rotated-local-test-456'
$orgID = $null
$ready = $false
for ($attempt=0; $attempt -lt 30; $attempt++) {
    try { if ((Invoke-RestMethod -Uri "$base/health").status -eq 'ok') { $ready = $true; break } } catch { Start-Sleep -Seconds 2 }
}
if (-not $ready) { throw 'Go API did not become healthy within 60 seconds' }
try {
    $bootstrap = docker compose run --rm --no-deps -e "PROVISION_ORG_NAME=Integration $tag" -e "PROVISION_ENV_NAME=Initial environment" -e "PROVISION_EMAIL=$email" -e "PROVISION_PASSWORD=$firstPassword" api /provision bootstrap | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $bootstrap.organization.id) { throw 'Bootstrap command failed' }
    $orgID = $bootstrap.organization.id
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    Invoke-RestMethod -Method Post -Uri "$base/auth/login" -WebSession $session -ContentType application/json -Body (@{email=$email;password=$firstPassword}|ConvertTo-Json -Compress) | Out-Null
    $assigned = @(Invoke-RestMethod -Uri "$base/environments" -WebSession $session)
    if ($assigned.Count -ne 1 -or $assigned[0].id -ne $bootstrap.environment.id -or $assigned[0].organization_id -ne $orgID) { throw 'Bootstrap admin did not receive an isolated environment' }
    try { Invoke-RestMethod -Uri "$base/environments/northstar/graph" -WebSession $session | Out-Null; throw 'New organization accessed Northstar' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw } }
    try { Invoke-RestMethod -Method Post -Uri "$base/organizations/$orgID/users" -ContentType application/json -Body '{"email":"unauthorized@example.invalid","password":"unauthorized-pass-123","role":"viewer"}' | Out-Null; throw 'Unauthenticated provisioning succeeded' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw } }
    $viewerEmail = "viewer-$tag@example.invalid"
    $viewerPassword = 'viewer-local-test-123'
    $viewer = Invoke-RestMethod -Method Post -Uri "$base/organizations/$orgID/users" -WebSession $session -ContentType application/json -Body (@{email=$viewerEmail;password=$viewerPassword;role='viewer'}|ConvertTo-Json -Compress)
    if ($viewer.role -ne 'viewer' -or $viewer.email -ne $viewerEmail) { throw 'Admin did not create viewer' }
    try { Invoke-RestMethod -Method Post -Uri "$base/organizations/$orgID/users" -WebSession $session -ContentType application/json -Body (@{email=$viewerEmail;password=$viewerPassword;role='viewer'}|ConvertTo-Json -Compress) | Out-Null; throw 'Duplicate account created' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 409) { throw } }
    $newEnvironment = Invoke-RestMethod -Method Post -Uri "$base/organizations/$orgID/environments" -WebSession $session -ContentType application/json -Body '{"name":"Second synthetic environment","description":"Provisioning test"}'
    if (-not $newEnvironment.id -or $newEnvironment.organization_id -ne $orgID) { throw 'Admin did not create environment' }
    try { Invoke-RestMethod -Method Post -Uri "$base/organizations/$orgID/environments" -WebSession $session -ContentType application/json -Body '{"name":"   "}' | Out-Null; throw 'Whitespace-only environment name accepted' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 422) { throw } }
    $viewerSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    Invoke-RestMethod -Method Post -Uri "$base/auth/login" -WebSession $viewerSession -ContentType application/json -Body (@{email=$viewerEmail;password=$viewerPassword}|ConvertTo-Json -Compress) | Out-Null
    $visible = Invoke-RestMethod -Uri "$base/environments" -WebSession $viewerSession
    if ($visible.Count -ne 2) { throw 'Viewer could not see organization environments' }
    try { Invoke-RestMethod -Method Post -Uri "$base/organizations/$orgID/environments" -WebSession $viewerSession -ContentType application/json -Body '{"name":"Forbidden environment"}' | Out-Null; throw 'Viewer created an environment' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw } }
    try { Invoke-RestMethod -Method Post -Uri "$base/auth/change-password" -WebSession $viewerSession -ContentType application/json -Body '{"current_password":"wrong-password","new_password":"viewer-new-local-456"}' | Out-Null; throw 'Incorrect current password accepted' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw } }
    Invoke-RestMethod -Method Post -Uri "$base/auth/change-password" -WebSession $viewerSession -ContentType application/json -Body (@{current_password=$viewerPassword;new_password='viewer-new-local-456'}|ConvertTo-Json -Compress) | Out-Null
    try { Invoke-RestMethod -Uri "$base/auth/me" -WebSession $viewerSession | Out-Null; throw 'Password change retained old session' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw } }
    try { Invoke-RestMethod -Method Post -Uri "$base/auth/login" -ContentType application/json -Body (@{email=$viewerEmail;password=$viewerPassword}|ConvertTo-Json -Compress) | Out-Null; throw 'Old password still worked' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw } }
    Invoke-RestMethod -Method Post -Uri "$base/auth/login" -ContentType application/json -Body (@{email=$viewerEmail;password='viewer-new-local-456'}|ConvertTo-Json -Compress) | Out-Null
    docker compose run --rm --no-deps -e "PROVISION_EMAIL=$email" -e "PROVISION_PASSWORD=$rotatedPassword" api /provision rotate-password | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Operator password rotation failed' }
    try { Invoke-RestMethod -Uri "$base/auth/me" -WebSession $session | Out-Null; throw 'Operator rotation retained old session' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw } }
    try { Invoke-RestMethod -Method Post -Uri "$base/auth/login" -ContentType application/json -Body (@{email=$email;password=$firstPassword}|ConvertTo-Json -Compress) | Out-Null; throw 'Old admin password still worked' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw } }
    Invoke-RestMethod -Method Post -Uri "$base/auth/login" -ContentType application/json -Body (@{email=$email;password=$rotatedPassword}|ConvertTo-Json -Compress) | Out-Null
    'Provisioning, organization roles, and password rotation passed.'
} finally {
    if ($orgID -and $orgID -match '^org-[0-9a-f]{32}$') {
        $sql = "BEGIN; DELETE FROM audit_records WHERE actor_id IN (SELECT user_id FROM memberships WHERE organization_id='$orgID') OR environment_id IN (SELECT id FROM environments WHERE organization_id='$orgID'); DELETE FROM sessions WHERE user_id IN (SELECT user_id FROM memberships WHERE organization_id='$orgID'); DELETE FROM environment_snapshots WHERE environment_id IN (SELECT id FROM environments WHERE organization_id='$orgID'); DELETE FROM memberships WHERE organization_id='$orgID'; DELETE FROM environments WHERE organization_id='$orgID'; DELETE FROM users WHERE email IN ('$email','viewer-$tag@example.invalid'); DELETE FROM organizations WHERE id='$orgID'; COMMIT;"
        docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U attackgraph -d attackgraph -c $sql | Out-Null
    }
}
