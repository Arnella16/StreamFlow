# 🔐 JWT Token Usage Guide

## Your JWT Token
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjhjMjVlNjIwYzkxMjlmMDllMmZhYmJjIiwidXNlcm5hbWUiOiJtdWtlc2hfdXNlciIsImV4cCI6MTc1NzY1NTAyMiwiaWF0IjoxNzU3NTY4NjIyfQ.PBRc4N9ASogHZ_ABs-TvE6FpRyPg0VPfiRQkrPPcjoQ
```

**User Details:**
- Username: `mukesh_user`
- Email: `mukesh@example.com` (updated to `mukesh_updated@example.com`)
- User ID: `68c25e620c9129f09e2fabbc`

## 🛠 How to Use the JWT Token

### 1. Command Line with cURL

#### Set the token as environment variable:
```bash
export TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjhjMjVlNjIwYzkxMjlmMDllMmZhYmJjIiwidXNlcm5hbWUiOiJtdWtlc2hfdXNlciIsImV4cCI6MTc1NzY1NTAyMiwiaWF0IjoxNzU3NTY4NjIyfQ.PBRc4N9ASogHZ_ABs-TvE6FpRyPg0VPfiRQkrPPcjoQ"
```

#### Get your profile:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/profile
```

#### Get all users:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/users
```

#### Get specific user by ID:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/users/68c25e620c9129f09e2fabbc
```

#### Update your profile:
```bash
curl -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "newemail@example.com"}' \
  http://localhost:3000/api/users/68c25e620c9129f09e2fabbc
```

#### Delete your account:
```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/users/68c25e620c9129f09e2fabbc
```

### 2. Using Postman or Insomnia

1. **Set Authorization Header:**
   - Key: `Authorization`
   - Value: `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjhjMjVlNjIwYzkxMjlmMDllMmZhYmJjIiwidXNlcm5hbWUiOiJtdWtlc2hfdXNlciIsImV4cCI6MTc1NzY1NTAyMiwiaWF0IjoxNzU3NTY4NjIyfQ.PBRc4N9ASogHZ_ABs-TvE6FpRyPg0VPfiRQkrPPcjoQ`

2. **Or use Bearer Token option:**
   - Select "Bearer Token" in Authorization tab
   - Paste token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjhjMjVlNjIwYzkxMjlmMDllMmZhYmJjIiwidXNlcm5hbWUiOiJtdWtlc2hfdXNlciIsImV4cCI6MTc1NzY1NTAyMiwiaWF0IjoxNzU3NTY4NjIyfQ.PBRc4N9ASogHZ_ABs-TvE6FpRyPg0VPfiRQkrPPcjoQ`

### 3. JavaScript/Node.js

#### Using fetch():
```javascript
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjhjMjVlNjIwYzkxMjlmMDllMmZhYmJjIiwidXNlcm5hbWUiOiJtdWtlc2hfdXNlciIsImV4cCI6MTc1NzY1NTAyMiwiaWF0IjoxNzU3NTY4NjIyfQ.PBRc4N9ASogHZ_ABs-TvE6FpRyPg0VPfiRQkrPPcjoQ";

// Get profile
fetch('http://localhost:3000/api/profile', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
})
.then(response => response.json())
.then(data => console.log(data));

// Update profile
fetch('http://localhost:3000/api/users/68c25e620c9129f09e2fabbc', {
  method: 'PATCH',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'newemail@example.com'
  })
})
.then(response => response.json())
.then(data => console.log(data));
```

#### Using axios:
```javascript
const axios = require('axios');

const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjhjMjVlNjIwYzkxMjlmMDllMmZhYmJjIiwidXNlcm5hbWUiOiJtdWtlc2hfdXNlciIsImV4cCI6MTc1NzY1NTAyMiwiaWF0IjoxNzU3NTY4NjIyfQ.PBRc4N9ASogHZ_ABs-TvE6FpRyPg0VPfiRQkrPPcjoQ";

const config = {
  headers: {
    'Authorization': `Bearer ${token}`
  }
};

// Get profile
axios.get('http://localhost:3000/api/profile', config)
  .then(response => console.log(response.data));

// Update profile
axios.patch('http://localhost:3000/api/users/68c25e620c9129f09e2fabbc', 
  { email: 'newemail@example.com' }, 
  config
).then(response => console.log(response.data));
```

### 4. Python

#### Using requests:
```python
import requests

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjhjMjVlNjIwYzkxMjlmMDllMmZhYmJjIiwidXNlcm5hbWUiOiJtdWtlc2hfdXNlciIsImV4cCI6MTc1NzY1NTAyMiwiaWF0IjoxNzU3NTY4NjIyfQ.PBRc4N9ASogHZ_ABs-TvE6FpRyPg0VPfiRQkrPPcjoQ"

headers = {
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json'
}

# Get profile
response = requests.get('http://localhost:3000/api/profile', headers=headers)
print(response.json())

# Update profile
data = {'email': 'newemail@example.com'}
response = requests.patch(
    'http://localhost:3000/api/users/68c25e620c9129f09e2fabbc', 
    json=data, 
    headers=headers
)
print(response.json())
```

## 📋 Available Protected Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/profile` | Get your profile |
| GET | `/api/users` | Get all users |
| GET | `/api/users/:id` | Get user by ID |
| PATCH | `/api/users/:id` | Update user (only your own) |
| DELETE | `/api/users/:id` | Delete user (only your own) |

## ⚠️ Important Notes

1. **Token Expiration:** This token expires in 24 hours from creation
2. **Authorization:** You can only modify your own profile (User ID: `68c25e620c9129f09e2fabbc`)
3. **Header Format:** Always use `Authorization: Bearer <token>` format
4. **HTTPS:** In production, always use HTTPS to protect the token

## 🔄 Getting a New Token

If your token expires, you can get a new one by logging in again:

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mukesh_user",
    "password": "securepass123"
  }'
```

## 🚫 What Happens Without Token

If you try to access protected endpoints without the token:

```bash
curl http://localhost:3000/api/profile
# Returns: {"error":"Missing authorization token"}
```

## ✅ Testing Token Validity

Quick test to see if your token is valid:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/profile
```

If you get user data back, your token is valid. If you get an error, the token is invalid or expired.
