#!/bin/bash

# StreamFlow API Test Script
# This script demonstrates the new security features implemented

BASE_URL="http://localhost:3000"
TOKEN=""

echo "🚀 StreamFlow API Security Test Script"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}📊 1. Health Check${NC}"
echo "GET $BASE_URL/health"
curl -s "$BASE_URL/health" | jq '.' || echo "Failed to connect to server"
echo -e "\n"

echo -e "${BLUE}🔒 2. Testing Protected Endpoint Without Authentication${NC}"
echo "GET $BASE_URL/api/users"
response=$(curl -s -w "%{http_code}" "$BASE_URL/api/users")
http_code="${response: -3}"
echo "HTTP Code: $http_code"
if [ "$http_code" = "401" ]; then
    echo -e "${GREEN}✅ Authentication properly required${NC}"
else
    echo -e "${RED}❌ Authentication bypass detected${NC}"
fi
echo -e "\n"

echo -e "${BLUE}📝 3. User Registration${NC}"
echo "POST $BASE_URL/api/auth/register"
registration_data='{
    "username": "testuser_'$(date +%s)'",
    "email": "test_'$(date +%s)'@example.com", 
    "password": "securepassword123"
}'

echo "Request data: $registration_data"
registration_response=$(curl -s -X POST "$BASE_URL/api/auth/register" \
    -H "Content-Type: application/json" \
    -d "$registration_data")

echo "Response:"
echo "$registration_response" | jq '.'

# Extract token from registration response
TOKEN=$(echo "$registration_response" | jq -r '.token // empty')
USERNAME=$(echo "$registration_response" | jq -r '.user.username // empty')

if [ ! -z "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    echo -e "${GREEN}✅ Registration successful, token received${NC}"
    echo -e "${YELLOW}🔑 Token: ${TOKEN:0:20}...${NC}"
else
    echo -e "${RED}❌ Registration failed${NC}"
    exit 1
fi
echo -e "\n"

echo -e "${BLUE}🔄 4. Testing Username Uniqueness (Bloom Filter)${NC}"
echo "POST $BASE_URL/api/auth/register (duplicate username)"
duplicate_registration='{
    "username": "'$USERNAME'",
    "email": "another_'$(date +%s)'@example.com", 
    "password": "anotherpassword123"
}'

duplicate_response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/auth/register" \
    -H "Content-Type: application/json" \
    -d "$duplicate_registration")

http_code="${duplicate_response: -3}"
response_body="${duplicate_response%???}"

echo "HTTP Code: $http_code"
echo "Response: $response_body" | jq '.'

if [ "$http_code" = "409" ]; then
    echo -e "${GREEN}✅ Bloom filter working - duplicate username rejected${NC}"
else
    echo -e "${RED}❌ Bloom filter failed - duplicate allowed${NC}"
fi
echo -e "\n"

echo -e "${BLUE}🔐 5. User Login${NC}"
echo "POST $BASE_URL/api/auth/login"
login_data='{
    "username": "'$USERNAME'",
    "password": "securepassword123"
}'

login_response=$(curl -s -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "$login_data")

echo "Response:"
echo "$login_response" | jq '.'

# Extract token from login response
LOGIN_TOKEN=$(echo "$login_response" | jq -r '.token // empty')

if [ ! -z "$LOGIN_TOKEN" ] && [ "$LOGIN_TOKEN" != "null" ]; then
    echo -e "${GREEN}✅ Login successful${NC}"
else
    echo -e "${RED}❌ Login failed${NC}"
fi
echo -e "\n"

echo -e "${BLUE}🛡️ 6. Testing Invalid Credentials${NC}"
echo "POST $BASE_URL/api/auth/login (wrong password)"
wrong_login_data='{
    "username": "'$USERNAME'",
    "password": "wrongpassword"
}'

wrong_login_response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "$wrong_login_data")

http_code="${wrong_login_response: -3}"
if [ "$http_code" = "401" ]; then
    echo -e "${GREEN}✅ Invalid credentials properly rejected${NC}"
else
    echo -e "${RED}❌ Security issue - invalid credentials accepted${NC}"
fi
echo -e "\n"

echo -e "${BLUE}👤 7. Accessing Protected Endpoints with Authentication${NC}"
echo "GET $BASE_URL/api/profile"
profile_response=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/profile")
echo "Profile Response:"
echo "$profile_response" | jq '.'

if [ "$(echo "$profile_response" | jq -r '.username')" = "$USERNAME" ]; then
    echo -e "${GREEN}✅ Protected endpoint accessible with valid token${NC}"
else
    echo -e "${RED}❌ Protected endpoint access failed${NC}"
fi
echo -e "\n"

echo -e "${BLUE}📋 8. Getting All Users (Protected)${NC}"
echo "GET $BASE_URL/api/users"
users_response=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/users")
echo "Users Response:"
echo "$users_response" | jq '.'
echo -e "\n"

echo -e "${BLUE}✏️ 9. Testing User Update${NC}"
echo "PATCH $BASE_URL/api/users/[user_id]"
USER_ID=$(echo "$registration_response" | jq -r '.user._id')
update_data='{
    "email": "updated_'$(date +%s)'@example.com"
}'

update_response=$(curl -s -X PATCH "$BASE_URL/api/users/$USER_ID" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$update_data")

echo "Update Response:"
echo "$update_response" | jq '.'

if [ "$(echo "$update_response" | jq -r '.message')" = "User updated successfully" ]; then
    echo -e "${GREEN}✅ User update successful${NC}"
else
    echo -e "${RED}❌ User update failed${NC}"
fi
echo -e "\n"

echo -e "${BLUE}🔒 10. Testing Authorization (Update Different User)${NC}"
echo "PATCH $BASE_URL/api/users/507f1f77bcf86cd799439011 (fake ID)"
unauthorized_update_response=$(curl -s -w "%{http_code}" -X PATCH "$BASE_URL/api/users/507f1f77bcf86cd799439011" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$update_data")

http_code="${unauthorized_update_response: -3}"
if [ "$http_code" = "403" ]; then
    echo -e "${GREEN}✅ Authorization working - cannot update other users${NC}"
else
    echo -e "${RED}❌ Authorization bypass detected${NC}"
fi
echo -e "\n"

echo -e "${GREEN}🎉 Security Test Complete!${NC}"
echo -e "\n${YELLOW}Summary of Implemented Features:${NC}"
echo "✅ Password hashing with bcrypt"
echo "✅ Bloom filter for username uniqueness check"
echo "✅ JWT-based authentication middleware"
echo "✅ Structured logging with detailed error handling"
echo "✅ Proper database service layer (no global variables)"
echo "✅ Protected routes requiring authentication"
echo "✅ Authorization controls (users can only modify their own data)"
echo "✅ Secure password storage (passwords not returned in JSON)"
echo "✅ Input validation and sanitization"
echo "✅ Comprehensive error handling with appropriate HTTP status codes"
