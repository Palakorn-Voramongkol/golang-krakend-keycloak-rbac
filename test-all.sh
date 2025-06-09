#!/usr/bin/env bash
# test-all.sh - Stylish Bash test script for KrakenD + Keycloak RBAC

set -euo pipefail
IFS=$'\n\t'

# Configuration
KRAKEND_URL="http://localhost:8081"
LOGIN_URL="$KRAKEND_URL/login"
CLIENT_ID="fiber-app"

# ANSI Colors
Green='\033[0;32m'
Red='\033[0;31m'
Reset='\033[0m'

print_header() {
  echo -e "\n----------------------------------------------------------------------"
  echo -e "➡️  $1"
  echo -e "----------------------------------------------------------------------"
}

wait_for_krakend() {
  echo -n "⏳ Waiting for KrakenD Gateway at $KRAKEND_URL/public..."
  until curl -s "$KRAKEND_URL/public" > /dev/null; do
    echo -n "."
    sleep 2
  done
  echo -e " ${Green}✅${Reset}"
}

get_token() {
  local username=$1
  local password=$2
  curl -s -X POST "$LOGIN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=$CLIENT_ID&username=$username&password=$password" |
    jq -r '.access_token'
}

failures=0

wait_for_krakend

# Phase 1: Acquire tokens
print_header "Phase 1: Acquiring JWTs for Alice (user) and Bob (admin) via /login"

aliceToken=$(get_token "alice" "password123")
if [[ -n "$aliceToken" && "$aliceToken" != "null" ]]; then
  echo -e "${Green}✅ SUCCESS${Reset}: Got token for Alice"
else
  echo -e "${Red}❌ FAILED${Reset}: Could not get token for Alice"
  ((failures++))
fi

bobToken=$(get_token "bob" "password123")
if [[ -n "$bobToken" && "$bobToken" != "null" ]]; then
  echo -e "${Green}✅ SUCCESS${Reset}: Got token for Bob"
else
  echo -e "${Red}❌ FAILED${Reset}: Could not get token for Bob"
  ((failures++))
fi

# Phase 2: Public
print_header "Phase 2: Testing Public Endpoint (/public)"
msg=$(curl -s "$KRAKEND_URL/public" | jq -r '.message')
if [[ "$msg" == "This is a public endpoint." ]]; then
  echo -e "${Green}✅ SUCCESS${Reset}: Public endpoint returned correct message."
else
  echo -e "${Red}❌ FAILED${Reset}: Unexpected public endpoint message: $msg"
  ((failures++))
fi

# Phase 3: Profile
print_header "Phase 3: Testing Protected Endpoint (/profile)"
profileUser=$(curl -s -H "Authorization: Bearer $aliceToken" "$KRAKEND_URL/profile" | jq -r '.user')
if [[ "$profileUser" == "alice" ]]; then
  echo -e "${Green}✅ SUCCESS${Reset}: Alice's /profile works."
else
  echo -e "${Red}❌ FAILED${Reset}: /profile returned wrong user."
  ((failures++))
fi

status=$(curl -s -o /dev/null -w '%{http_code}' "$KRAKEND_URL/profile")
if [[ "$status" == "401" ]]; then
  echo -e "${Green}✅ SUCCESS${Reset}: /profile correctly blocked unauthenticated user."
else
  echo -e "${Red}❌ FAILED${Reset}: /profile status for no token was $status (expected 401)"
  ((failures++))
fi

# Phase 4: /user
print_header "Phase 4: Testing Role-Based Endpoint (/user)"
msg=$(curl -s -H "Authorization: Bearer $aliceToken" "$KRAKEND_URL/user" | jq -r '.message')
if [[ "$msg" == *"payroll"* ]]; then
  echo -e "${Green}✅ SUCCESS${Reset}: Alice (user) accessed /user endpoint."
else
  echo -e "${Red}❌ FAILED${Reset}: Alice /user response unexpected: $msg"
  ((failures++))
fi

status=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $bobToken" "$KRAKEND_URL/user")
if [[ "$status" == "403" ]]; then
  echo -e "${Green}✅ SUCCESS${Reset}: Bob correctly denied at /user"
else
  echo -e "${Red}❌ FAILED${Reset}: /user for Bob returned $status, expected 403"
  ((failures++))
fi

# Phase 5: /admin
print_header "Phase 5: Testing Role-Based Endpoint (/admin)"
status=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $aliceToken" "$KRAKEND_URL/admin")
if [[ "$status" == "403" ]]; then
  echo -e "${Green}✅ SUCCESS${Reset}: Alice denied at /admin"
else
  echo -e "${Red}❌ FAILED${Reset}: Alice /admin status was $status"
  ((failures++))
fi

msg=$(curl -s -H "Authorization: Bearer $bobToken" "$KRAKEND_URL/admin" | jq -r '.message')
if [[ "$msg" == *"item count"* ]]; then
  echo -e "${Green}✅ SUCCESS${Reset}: Bob (admin) accessed /admin"
else
  echo -e "${Red}❌ FAILED${Reset}: Bob /admin response unexpected: $msg"
  ((failures++))
fi

# Summary
echo -e "\n----------------------------------------------------------------------"
if [[ "$failures" -eq 0 ]]; then
  echo -e "${Green}🎉 All tests passed! The system is working as expected! 🎉${Reset}"
  exit 0
else
  echo -e "${Red}⚠️  Some tests failed: $failures failure(s).${Reset}"
  exit 1
fi
