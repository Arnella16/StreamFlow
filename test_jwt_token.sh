#!/bin/bash

# Your JWT Token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjhjMjVlNjIwYzkxMjlmMDllMmZhYmJjIiwidXNlcm5hbWUiOiJtdWtlc2hfdXNlciIsImV4cCI6MTc1NzY1NTAyMiwiaWF0IjoxNzU3NTY4NjIyfQ.PBRc4N9ASogHZ_ABs-TvE6FpRyPg0VPfiRQkrPPcjoQ"
USER_ID="68c25e620c9129f09e2fabbc"

echo "🔐 Testing JWT Token Usage"
echo "=========================="
echo ""

echo "🔍 1. Get your profile:"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/profile | jq .
echo ""

echo "👥 2. Get all users:"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/users | jq .
echo ""

echo "✏️ 3. Update your email:"
curl -s -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test_updated@example.com"}' \
  http://localhost:3000/api/users/$USER_ID | jq .
echo ""

echo "🔍 4. Get your updated profile:"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/profile | jq .
echo ""

echo "🚫 5. Try without token (should fail):"
curl -s http://localhost:3000/api/profile | jq .
echo ""

echo "✅ JWT Token test complete!"
echo ""
echo "Your token: $TOKEN"
echo "Your User ID: $USER_ID"
