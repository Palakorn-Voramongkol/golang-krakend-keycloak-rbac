# test-all.ps1
# End-to-end test script for the KrakenD + Keycloak RBAC implementation.

# --- Configuration ---
# The URL of the KrakenD API Gateway. Ensure this matches your docker-compose port mapping.
$KRAKEND_URL = "http://localhost:8081"
$LOGIN_URL   = "$KRAKEND_URL/login"
$CLIENT_ID   = "fiber-app"

# --- Style Definitions ---
# ANSI Colors for readable output in modern terminals.
$Green  = "`e[32m"
$Red    = "`e[31m"
$Yellow = "`e[33m"
$Reset  = "`e[0m"

# --- Helper Functions ---
# Prints a formatted header to the console to separate test phases.
function Print-Header($msg) {
    Write-Host ""
    Write-Host ("-" * 70)
    Write-Host "➡️  $msg"
    Write-Host ("-" * 70)
}

# --- Pre-flight Check ---
# Wait for the KrakenD Gateway to be available before running tests.
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

# --- Test Phases ---

# Phase 1: Acquire JWTs by logging in as Alice (user) and Bob (admin).
Print-Header "Phase 1: Acquiring JWTs for Alice (user) and Bob (admin)"
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
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Could not get token for Alice"); $failures++
}

$bobToken = Get-Token "bob" "password123"
if ($bobToken) {
    Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Got token for Bob")
} else {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Could not get token for Bob"); $failures++
}

# Phase 2: Test the unprotected public endpoint.
Print-Header "Phase 2: Testing Public Endpoint (/public)"
try {
    $msg = (Invoke-RestMethod "$KRAKEND_URL/public").message
    if ($msg -eq "This is a public endpoint.") {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Public endpoint returned correct message.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": Unexpected public endpoint message: $msg"); $failures++
    }
} catch {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Error calling /public"); $failures++
}

# Phase 3: Test the /profile endpoint, which requires a valid token.
Print-Header "Phase 3: Testing Profile Endpoint (/profile)"
try {
    $response = Invoke-RestMethod "$KRAKEND_URL/profile" -Headers @{ Authorization = "Bearer $aliceToken" }
    if ($response.user -eq "alice") {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Alice's /profile works.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": /profile returned wrong user."); $failures++
    }
} catch {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": /profile call failed for Alice"); $failures++
}

try {
    # Verify that an unauthenticated request to /profile is rejected with 401 Unauthorized.
    $status = (Invoke-WebRequest "$KRAKEND_URL/profile" -UseBasicParsing -SkipHttpErrorCheck).StatusCode
    if ($status -eq 401) {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": /profile correctly blocked unauthenticated user.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": /profile status for no token was $status (expected 401)"); $failures++
    }
} catch {
    Write-Host ($Green + "✅ SUCCESS" + $Reset + ": /profile blocked unauthenticated access as expected.")
}

# Phase 4: Test the /user endpoint for fetching user-specific data.
Print-Header "Phase 4: Testing User Data Endpoint (/user)"
try {
    $response = Invoke-RestMethod "$KRAKEND_URL/user" -Headers @{ Authorization = "Bearer $aliceToken" }
    if ($response.username -eq "alice") {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Alice accessed /user and got her user data.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": /user response for Alice was unexpected."); $failures++
    }
} catch {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Alice failed to call /user"); $failures++
}

try {
    # Verify that Bob (admin) is also allowed to access the /user endpoint.
    $response = Invoke-RestMethod "$KRAKEND_URL/user" -Headers @{ Authorization = "Bearer $bobToken" }
    if ($response.username -eq "bob") {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Bob (admin) correctly allowed at /user.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": /user for Bob returned wrong user."); $failures++
    }
} catch {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Bob (admin) was unexpectedly blocked at /user"); $failures++
}

# Phase 5: Test the /payroll endpoint, which has more restrictive permissions.
Print-Header "Phase 5: Testing Payroll Endpoint (/payroll)"
try {
    $msg = (Invoke-RestMethod "$KRAKEND_URL/payroll" -Headers @{ Authorization = "Bearer $aliceToken" }).message
    if ($msg -like "*payroll*") {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Alice accessed /payroll.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": Unexpected response from /payroll: $msg"); $failures++
    }
} catch {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Alice failed to call /payroll"); $failures++
}

try {
    # Verify that Bob (admin) is blocked from /payroll, as the 'admin' role lacks the specific 'hr:payroll:view' permission.
    $status = (Invoke-WebRequest "$KRAKEND_URL/payroll" -UseBasicParsing -SkipHttpErrorCheck -Headers @{ Authorization = "Bearer $bobToken" }).StatusCode
    if ($status -eq 403) {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Bob correctly denied at /payroll.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": /payroll for Bob returned $status (expected 403)"); $failures++
    }
} catch {
    Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Bob blocked at /payroll as expected.")
}


# Phase 6: Test the /admin endpoint, which is restricted to the 'admin' role.
Print-Header "Phase 6: Testing Admin Endpoint (/admin)"
try {
    $status = (Invoke-WebRequest "$KRAKEND_URL/admin" -UseBasicParsing -SkipHttpErrorCheck -Headers @{ Authorization = "Bearer $aliceToken" }).StatusCode
    if ($status -eq 403) {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Alice correctly denied at /admin.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": /admin for Alice status was $status (expected 403)"); $failures++
    }
} catch {
    Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Alice blocked at /admin as expected.")
}

try {
    $response = Invoke-RestMethod "$KRAKEND_URL/admin" -Headers @{ Authorization = "Bearer $bobToken" }
    if ($response.message -like "*item count*") {
        Write-Host ($Green + "✅ SUCCESS" + $Reset + ": Bob (admin) accessed /admin.")
    } else {
        Write-Host ($Red + "❌ FAILED" + $Reset + ": /admin response for Bob was unexpected: $($response.message)"); $failures++
    }
} catch {
    Write-Host ($Red + "❌ FAILED" + $Reset + ": Bob failed to call /admin"); $failures++
}

# --- Final Summary ---
Write-Host ""
Write-Host ("-" * 70)
if ($failures -eq 0) {
    Write-Host ($Green + "🎉 All tests passed! The system is working as expected! 🎉" + $Reset)
    exit 0
} else {
    Write-Host ($Red + "⚠️  Some tests failed: $failures failure(s)." + $Reset)
    exit 1
}
