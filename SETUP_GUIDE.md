# KARE Q&A API - Setup Guide

## Quick Start

### 1. Prerequisites

- Docker and Docker Compose installed
- OpenAI API key

### 2. Environment Setup

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Edit `.env` and fill in the required values:
```bash
# Required: Your OpenAI API key
OPENAI_API_KEY=sk-your-actual-openai-api-key

# Required: Generate a secure JWT secret (run this command):
# openssl rand -hex 32
JWT_SECRET_KEY=your-generated-secret-key-here

# MongoDB connection (default is fine for Docker)
MONGODB_URI=mongodb://mongodb:27017
MONGODB_DATABASE=kare_qa_db

# Token expiration (optional, default 24 hours)
ACCESS_TOKEN_EXPIRE_HOURS=24
```

### 3. Generate JWT Secret Key

Run this command to generate a secure secret key:

**Linux/Mac:**
```bash
openssl rand -hex 32
```

**Windows PowerShell:**
```powershell
$bytes = New-Object byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
[BitConverter]::ToString($bytes) -replace '-','' | Write-Output
```

Copy the output and paste it as `JWT_SECRET_KEY` in your `.env` file.

### 4. Start the Services

Build and start all services (API + MongoDB):

```bash
docker compose up --build
```

The API will be available at `http://localhost:8000`

MongoDB will be available at `localhost:27017`

### 5. Verify Installation

Check the health endpoint:

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{"status": "ok"}
```

---

## Testing the API

### 1. Signup

```bash
curl -X POST http://localhost:8000/signup \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test.user@klu.ac.in",
    "password": "SecurePass123",
    "department": "Computer Science",
    "phone_number": "+919876543210"
  }'
```

Save the `access_token` from the response.

### 2. Login

```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test.user@klu.ac.in",
    "password": "SecurePass123"
  }'
```

### 3. Get User Profile

```bash
curl -X GET http://localhost:8000/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 4. Ask a Question

```bash
curl -X POST http://localhost:8000/ask \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "question": "What are the functions of the eye?"
  }'
```

### 5. Logout

```bash
curl -X POST http://localhost:8000/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## Development

### Running without Docker

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Start MongoDB locally:
```bash
docker run -d -p 27017:27017 --name mongodb mongo:8.0
```

3. Update `.env`:
```bash
MONGODB_URI=mongodb://localhost:27017
```

4. Run the API:
```bash
uvicorn src.api:app --reload --host 0.0.0.0 --port 8000
```

### Accessing MongoDB

Connect to MongoDB container:
```bash
docker exec -it kare_mongodb mongosh
```

View users:
```javascript
use kare_qa_db
db.users.find().pretty()
```

View sessions:
```javascript
db.sessions.find().pretty()
```

---

## Troubleshooting

### Issue: "JWT_SECRET_KEY is not configured"

**Solution:** Make sure you've set `JWT_SECRET_KEY` in your `.env` file with a secure random value.

### Issue: "Could not connect to MongoDB"

**Solution:** 
1. Check if MongoDB container is running: `docker ps`
2. Check MongoDB logs: `docker logs kare_mongodb`
3. Verify `MONGODB_URI` in `.env` file

### Issue: "Email must end with @klu.ac.in"

**Solution:** The API only allows emails ending with `@klu.ac.in`. Update your email or modify the whitelist pattern in `src/auth.py`.

### Issue: "Password too weak"

**Solution:** Password must:
- Be at least 8 characters long
- Contain at least one uppercase letter
- Contain at least one lowercase letter
- Contain at least one digit

---

## API Documentation

Full API documentation is available at:
- **File:** `docs/API_DOCUMENTATION.md`
- **Interactive Docs (Swagger):** http://localhost:8000/docs (when server is running)
- **ReDoc:** http://localhost:8000/redoc (when server is running)

---

## Architecture

```
┌─────────────────┐
│   Frontend      │
│  (Web/Mobile)   │
└────────┬────────┘
         │ HTTP + JWT
         ▼
┌─────────────────┐      ┌──────────────┐
│   FastAPI       │◄────►│   MongoDB    │
│   (API Server)  │      │  (Database)  │
└────────┬────────┘      └──────────────┘
         │
         ▼
┌─────────────────┐
│   OpenAI API    │
│  (Embeddings &  │
│   Completions)  │
└─────────────────┘
```

## Security Notes

1. **Production Deployment:**
   - Always use HTTPS
   - Use a strong, unique JWT secret key
   - Set proper CORS policies
   - Use environment-specific `.env` files
   - Enable MongoDB authentication
   - Use secure password hashing (already implemented with bcrypt)

2. **Email Whitelist:**
   - Currently allows only `@klu.ac.in` emails
   - Modify `WHITELISTED_EMAIL_PATTERN` in `src/auth.py` to change this

3. **Token Expiration:**
   - Default: 24 hours
   - Adjust `ACCESS_TOKEN_EXPIRE_HOURS` in `.env`
   - Implement refresh tokens for better UX (not yet implemented)

---

## Next Steps

1. ✅ Set up environment variables
2. ✅ Start services with Docker Compose
3. ✅ Test authentication endpoints
4. ✅ Share API documentation with frontend team
5. 🔄 Implement frontend integration
6. 🔄 Deploy to production server

---

## Support

For questions or issues:
- Check `docs/API_DOCUMENTATION.md`
- Review error messages in API responses
- Check Docker logs: `docker compose logs -f`

**Version:** 1.0.0  
**Last Updated:** November 7, 2025
