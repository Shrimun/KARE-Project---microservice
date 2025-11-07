# KARE Question Answering Microservice

A production-ready FastAPI microservice that provides authenticated question-answering capabilities using Retrieval-Augmented Generation (RAG). The service includes user authentication, session management, and answers natural language questions using semantic search combined with OpenAI's language models.

## Features

### Authentication & Security
- **JWT-based Authentication**: Secure token-based authentication with Bearer tokens
- **User Management**: Complete signup/login/logout flow with session tracking
- **Email Whitelisting**: Restricted to authorized email domains (@klu.ac.in)
- **Password Security**: Bcrypt hashing with strength validation
- **Session Management**: MongoDB-backed sessions with automatic expiration

### Question Answering
- **Semantic Search**: ChromaDB-powered vector similarity search for relevant context retrieval
- **Source Attribution**: Every answer cites specific document chunks for transparency
- **Streaming Support**: Optional streaming responses for real-time answer generation
- **Protected Endpoints**: All Q&A endpoints require authentication

### Production-Ready
- **Robust Error Handling**: Unified error format with automatic retry/backoff for transient failures
- **MongoDB Integration**: Persistent user and session storage
- **Docker Support**: Complete containerized setup with MongoDB
- **Comprehensive Logging**: Detailed logging for debugging and monitoring

## Quick Start with Docker

```bash
# 1. Set up environment
cp .env.example .env

# 2. Edit .env and add required values:
#    - OPENAI_API_KEY
#    - JWT_SECRET_KEY (generate with: openssl rand -hex 32)
nano .env

# 3. Start all services (API + MongoDB)
docker compose up --build

# The API will be available at http://localhost:8000
```

## API Endpoints

### Authentication
- `POST /signup` - Register new user (requires @klu.ac.in email)
- `POST /login` - Login and get access token
- `POST /logout` - Logout and invalidate session
- `GET /me` - Get current user profile

### Question Answering (Authenticated)
- `POST /ask` - Ask a question and get AI-generated answer
- `GET /health` - Health check endpoint

### Interactive Documentation
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Documentation

### For Developers
- **[Setup Guide](SETUP_GUIDE.md)** - Complete setup instructions and troubleshooting
- **[API Documentation](docs/API_DOCUMENTATION.md)** - Comprehensive API reference with code examples
- **[Architecture](docs/architecture.md)** - System design, data flow, and components
- **[Directory Structure](docs/directory-structure.md)** - Project layout and file purposes

### Original Docs
- **[Getting Started](docs/getting-started.md)** - Original setup and configuration
- **[Examples](docs/examples.md)** - Sample requests and responses

## Technology Stack

- **FastAPI** - Modern async web framework
- **MongoDB** - User and session database (Motor async driver)
- **JWT** - Token-based authentication (python-jose)
- **ChromaDB** - Vector database for document embeddings
- **OpenAI API** - Embeddings and text generation
- **Bcrypt** - Password hashing (passlib)
- **Docker** - Containerization and deployment

## Development Setup (Without Docker)

```bash
# Install dependencies
pip install -r requirements.txt

# Start MongoDB
docker run -d -p 27017:27017 --name mongodb mongo:8.0

# Update .env
MONGODB_URI=mongodb://localhost:27017

# Build document index
make index

# Start API server
make dev
```

## Testing the API

### 1. Signup
```bash
curl -X POST http://localhost:8000/signup \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john.doe@klu.ac.in",
    "password": "SecurePass123",
    "department": "Computer Science",
    "phone_number": "+919876543210"
  }'
```

### 2. Ask Question (with token)
```bash
curl -X POST http://localhost:8000/ask \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "question": "What are the functions of the eye?"
  }'
```

See [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) for complete examples in JavaScript, TypeScript, React Native, and Python.

## Security Features

1. **Email Whitelisting**: Only @klu.ac.in emails allowed
2. **Password Strength**: Enforced minimum requirements
3. **JWT Tokens**: Secure, expiring tokens (24h default)
4. **Session Tracking**: IP and user-agent logging
5. **Bcrypt Hashing**: Industry-standard password encryption

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

## Environment Variables

Required variables in `.env`:

```bash
# OpenAI
OPENAI_API_KEY=sk-your-key

# MongoDB
MONGODB_URI=mongodb://mongodb:27017
MONGODB_DATABASE=kare_qa_db

# JWT Authentication
JWT_SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_HOURS=24
```

Generate JWT secret: `openssl rand -hex 32`

## Support

For questions or issues:
- Check [SETUP_GUIDE.md](SETUP_GUIDE.md) for setup help
- Review [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) for API details
- Check logs: `docker compose logs -f`

## License

MIT License - See LICENSE file for details