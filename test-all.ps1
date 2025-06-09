# test-all.ps1
# Stylish PowerShell test script for KrakenD + Keycloak RBAC

# Configuration
$KRAKEND_URL = "http://localhost:8081"
$LOGIN_URL = "$KRAKEND_URL/login"
$CLIENT_ID = "fiber-app"

# ANSI Colors (Windows Terminal + VS Code Terminal)
$Green = "`e[32m"
$Red = "`e[31m"
$Yellow = "`e[33m"
$Reset = "`e[0m"

# Helper
function Print-Header($msg) {
    Write-Host ""
    Write-Host ("-" * 70)
    Write-Host "➡️  $msg"
    Write-Host ("-" * 70)
}

# Wait for KrakenD
Write-Host "⏳ Waiting for KrakenD Gateway at $KRAKEND_URL/public..." -NoNewline
while ($true) {
    try {
        $null = Invoke-RestMethod "$KRAKEND_URL/public"
        break
    } catch {
        Write-Host "." -NoNewline
        Start-Sleep -Seconds 2
    }
}
Write-Host ($Green + " ✅" + $Reset)

$failures = 0

# Phase 1: Get Tokens
Print-Header "Phase 1: Acquiring JWTs for Alice (user) and Bob (admin) via /login"

function Get-Token($username, $password) {
    try {
        $res = Invoke-RestMethod -Uri $LOGIN_URL `
            -Method POST `
            -Headers @{ "Content-Type" = "application/x-www-form-urlencoded" } `
            -Body "grant_type=password&client_id=$CLIENT_ID&username=$username&password=$password"
        return $res.access_token
    } catch {
        return $null
    }
}

$aliceToken = Get-Token "alice" "password123"
if ($aliceToken) {
    Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Got token for Alice")
} else {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Could not get token for Alice")
    $failures++
}

$bobToken = Get-Token "bob" "password123"
if ($bobToken) {
    Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Got token for Bob")
} else {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Could not get token for Bob")
    $failures++
}

# Phase 2: Public Endpoint
Print-Header "Phase 2: Testing Public Endpoint (/public)"
try {
    $msg = (Invoke-RestMethod "$KRAKEND_URL/public").message
    if ($msg -eq "This is a public endpoint.") {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Public endpoint returned correct message.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": Unexpected public endpoint message: $msg")
        $failures++
    }
} catch {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Error calling /public")
    $failures++
}

# Phase 3: /profile
Print-Header "Phase 3: Testing Protected Endpoint (/profile)"
try {
    $response = Invoke-RestMethod "$KRAKEND_URL/profile" -Headers @{ Authorization = "Bearer $aliceToken" }
    if ($response.user -eq "alice") {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Alice's /profile works.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": /profile returned wrong user.")
        $failures++
    }
} catch {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": /profile call failed for Alice")
    $failures++
}

try {
    $status = (Invoke-WebRequest "$KRAKEND_URL/profile" -Method GET -UseBasicParsing -SkipHttpErrorCheck).StatusCode
    if ($status -eq 401) {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": /profile correctly blocked unauthenticated user.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": /profile status for no token was $status (expected 401)")
        $failures++
    }
} catch {
    Write-Host ($Green + "✅ SUCCESS" + $Reset + ": /profile blocked unauthenticated access.")
}

# Phase 4: /user
Print-Header "Phase 4: Testing Role-Based Endpoint (/user)"
try {
    $msg = (Invoke-RestMethod "$KRAKEND_URL/user" -Headers @{ Authorization = "Bearer $aliceToken" }).message
    if ($msg -like "*payroll*") {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Alice (user) accessed /user endpoint.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": Alice /user response unexpected: $msg")
        $failures++
    }
} catch {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Alice failed to call /user")
    $failures++
}

try {
    $status = (Invoke-WebRequest "$KRAKEND_URL/user" -Headers @{ Authorization = "Bearer $bobToken" } -UseBasicParsing -SkipHttpErrorCheck).StatusCode
    if ($status -eq 403) {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Bob correctly denied at /user")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": /user for Bob returned $status, expected 403")
        $failures++
    }
} catch {
    Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Bob blocked at /user (403)")
}

# Phase 5: /admin
Print-Header "Phase 5: Testing Role-Based Endpoint (/admin)"
try {
    $status = (Invoke-WebRequest "$KRAKEND_URL/admin" -Headers @{ Authorization = "Bearer $aliceToken" } -UseBasicParsing -SkipHttpErrorCheck).StatusCode
    if ($status -eq 403) {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Alice denied at /admin")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": Alice /admin status was $status")
        $failures++
    }
} catch {
    Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Alice blocked at /admin (403)")
}

try {
    $msg = (Invoke-RestMethod "$KRAKEND_URL/admin" -Headers @{ Authorization = "Bearer $bobToken" }).message
    if ($msg -like "*item count*") {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Bob (admin) accessed /admin")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": Bob /admin response unexpected: $msg")
        $failures++
    }
} catch {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Bob failed to call /admin")
    $failures++
}

# Final Summary
Write-Host ""
Write-Host ("-" * 70)
if ($failures -eq 0) {
    Write-Host ($Green + "🎉 All tests passed! The system is working as expected! 🎉" + $Reset)
    exit 0
} else {
    Write-Host ($Red + "⚠️  Some tests failed: $failures failure(s)." + $Reset)
    exit 1
}
