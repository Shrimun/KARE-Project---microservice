# KARE Question Answering API - Developer Documentation

## Table of Contents
1. [Overview](#overview)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
4. [Error Handling](#error-handling)
5. [Code Examples](#code-examples)

---

## Overview

This is a REST API for the KARE Question Answering microservice. It provides authentication and question-answering capabilities for students and faculty.

**Base URL:** `http://localhost:8000` (development)

**API Version:** 1.0.0

---

## Authentication

The API uses **JWT (JSON Web Token) Bearer authentication**. After signup or login, you'll receive an access token that must be included in subsequent requests.

### Token Usage

Include the token in the `Authorization` header:

```
Authorization: Bearer <your_access_token>
```

### Token Expiration

Tokens expire after **24 hours** by default. After expiration, users must login again to get a new token.

---

## API Endpoints

### 1. User Signup

**Endpoint:** `POST /signup`

**Description:** Register a new user account. Email must end with `@klu.ac.in`.

**Authentication:** Not required

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "john.doe@klu.ac.in",
  "password": "SecurePass123",
  "department": "Computer Science",
  "phone_number": "+919876543210"
}
```

**Field Validation:**
- `name`: 2-100 characters, required
- `email`: Valid email ending with `@klu.ac.in`, required
- `password`: Minimum 8 characters with at least one uppercase, one lowercase, and one digit, required
- `department`: 2-100 characters, required
- `phone_number`: Valid Indian phone number (10 digits or +91 format), required

**Success Response (201 Created):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "user_id": "abc123xyz",
    "name": "John Doe",
    "email": "john.doe@klu.ac.in",
    "department": "Computer Science",
    "phone_number": "+919876543210",
    "created_at": "2025-11-07T14:30:00Z"
  }
}
```

**Error Responses:**
- `400 Bad Request`: Invalid email domain, weak password, or invalid phone number
- `409 Conflict`: User with this email already exists
- `422 Unprocessable Entity`: Validation errors

---

### 2. User Login

**Endpoint:** `POST /login`

**Description:** Authenticate with email and password to get an access token.

**Authentication:** Not required

**Request Body:**
```json
{
  "email": "john.doe@klu.ac.in",
  "password": "SecurePass123"
}
```

**Success Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "user_id": "abc123xyz",
    "name": "John Doe",
    "email": "john.doe@klu.ac.in",
    "department": "Computer Science",
    "phone_number": "+919876543210",
    "created_at": "2025-11-07T14:30:00Z"
  }
}
```

**Error Responses:**
- `401 Unauthorized`: Incorrect email or password
- `403 Forbidden`: Account is deactivated

---

### 3. Get Current User Profile

**Endpoint:** `GET /me`

**Description:** Get the current authenticated user's profile information.

**Authentication:** Required (Bearer token)

**Request Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200 OK):**
```json
{
  "user_id": "abc123xyz",
  "name": "John Doe",
  "email": "john.doe@klu.ac.in",
  "department": "Computer Science",
  "phone_number": "+919876543210",
  "created_at": "2025-11-07T14:30:00Z"
}
```

**Error Responses:**
- `401 Unauthorized`: Invalid or expired token
- `404 Not Found`: User not found

---

### 4. Logout

**Endpoint:** `POST /logout`

**Description:** Logout the current user and invalidate their session.

**Authentication:** Required (Bearer token)

**Request Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200 OK):**
```json
{
  "message": "Successfully logged out",
  "logged_out_at": "2025-11-07T15:45:00Z"
}
```

**Error Responses:**
- `401 Unauthorized`: Invalid or expired token

---

### 5. Ask Question

**Endpoint:** `POST /ask`

**Description:** Ask a question and receive an AI-generated answer with source citations.

**Authentication:** Required (Bearer token)

**Request Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "question": "What are the main functions of the cornea?"
}
```

**Query Parameters:**
- `stream` (optional, boolean): Set to `true` for streaming responses. Default: `false`

**Success Response (200 OK):**
```json
{
  "answer": "The cornea has several main functions including refracting light...",
  "sources": [
    {
      "chunk_id": "chunk_123",
      "document": "Anatomy of Eye.pdf",
      "score": 0.95
    },
    {
      "chunk_id": "chunk_456",
      "document": "Visual Impairments.pdf",
      "score": 0.87
    }
  ]
}
```

**Streaming Response:**

When `stream=true`, responses are sent as Server-Sent Events (SSE) with JSON payloads:

```json
{"event": "context", "data": {"question": "...", "sources": [...]}}
{"event": "answer", "data": {"answer": "...", "sources": [...]}}
```

**Error Responses:**
- `401 Unauthorized`: Invalid or expired token
- `422 Unprocessable Entity`: Invalid question (too short, too long, or empty)
- `502 Bad Gateway`: OpenAI service unavailable

---

### 6. Health Check

**Endpoint:** `GET /health`

**Description:** Check if the API is running.

**Authentication:** Not required

**Success Response (200 OK):**
```json
{
  "status": "ok"
}
```

---

### 7. Service Info

**Endpoint:** `GET /`

**Description:** Get basic service information.

**Authentication:** Not required

**Success Response (200 OK):**
```json
{
  "service": "Question Answering Service",
  "version": "1.0.0",
  "endpoints": {
    "/ask": "POST endpoint to ask a question",
    "/health": "GET health check endpoint"
  }
}
```

---

## Error Handling

All errors follow a consistent JSON structure:

```json
{
  "error": {
    "status": 400,
    "message": "Email must end with @klu.ac.in",
    "details": null
  }
}
```

### Common HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication failed or token invalid
- `403 Forbidden`: Access denied
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource already exists
- `422 Unprocessable Entity`: Validation failed
- `500 Internal Server Error`: Server error
- `502 Bad Gateway`: External service unavailable

---

## Code Examples

### JavaScript/TypeScript (React/Next.js)

#### 1. Signup
```typescript
async function signup(userData: {
  name: string;
  email: string;
  password: string;
  department: string;
  phone_number: string;
}) {
  const response = await fetch('http://localhost:8000/signup', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(userData),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error.message);
  }

  const data = await response.json();
  
  // Store token in localStorage or secure cookie
  localStorage.setItem('access_token', data.access_token);
  localStorage.setItem('user', JSON.stringify(data.user));
  
  return data;
}
```

#### 2. Login
```typescript
async function login(email: string, password: string) {
  const response = await fetch('http://localhost:8000/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error.message);
  }

  const data = await response.json();
  
  // Store token
  localStorage.setItem('access_token', data.access_token);
  localStorage.setItem('user', JSON.stringify(data.user));
  
  return data;
}
```

#### 3. Ask Question (Authenticated)
```typescript
async function askQuestion(question: string) {
  const token = localStorage.getItem('access_token');
  
  if (!token) {
    throw new Error('Not authenticated');
  }

  const response = await fetch('http://localhost:8000/ask', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ question }),
  });

  if (!response.ok) {
    if (response.status === 401) {
      // Token expired, redirect to login
      localStorage.removeItem('access_token');
      window.location.href = '/login';
      return;
    }
    
    const error = await response.json();
    throw new Error(error.error.message);
  }

  return await response.json();
}
```

#### 4. Logout
```typescript
async function logout() {
  const token = localStorage.getItem('access_token');
  
  if (token) {
    await fetch('http://localhost:8000/logout', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });
  }
  
  // Clear local storage
  localStorage.removeItem('access_token');
  localStorage.removeItem('user');
  
  // Redirect to login
  window.location.href = '/login';
}
```

#### 5. Get Current User
```typescript
async function getCurrentUser() {
  const token = localStorage.getItem('access_token');
  
  if (!token) {
    throw new Error('Not authenticated');
  }

  const response = await fetch('http://localhost:8000/me', {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    if (response.status === 401) {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
      return;
    }
    throw new Error('Failed to get user');
  }

  return await response.json();
}
```

---

### React Native (Mobile App)

#### AsyncStorage Setup
```typescript
import AsyncStorage from '@react-native-async-storage/async-storage';

// Store token
await AsyncStorage.setItem('access_token', data.access_token);

// Get token
const token = await AsyncStorage.getItem('access_token');

// Remove token
await AsyncStorage.removeItem('access_token');
```

#### API Service Example
```typescript
import AsyncStorage from '@react-native-async-storage/async-storage';

const API_BASE_URL = 'http://localhost:8000'; // Use your server IP for real devices

class ApiService {
  async signup(userData) {
    const response = await fetch(`${API_BASE_URL}/signup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userData),
    });

    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error.message);
    }

    await AsyncStorage.setItem('access_token', data.access_token);
    await AsyncStorage.setItem('user', JSON.stringify(data.user));
    
    return data;
  }

  async askQuestion(question) {
    const token = await AsyncStorage.getItem('access_token');
    
    const response = await fetch(`${API_BASE_URL}/ask`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ question }),
    });

    if (!response.ok) {
      if (response.status === 401) {
        await AsyncStorage.removeItem('access_token');
        throw new Error('Session expired');
      }
      const error = await response.json();
      throw new Error(error.error.message);
    }

    return await response.json();
  }
}

export default new ApiService();
```

---

### Python (for testing or backend integration)

```python
import requests

BASE_URL = "http://localhost:8000"

# Signup
def signup(user_data):
    response = requests.post(f"{BASE_URL}/signup", json=user_data)
    response.raise_for_status()
    return response.json()

# Login
def login(email, password):
    response = requests.post(
        f"{BASE_URL}/login",
        json={"email": email, "password": password}
    )
    response.raise_for_status()
    data = response.json()
    return data["access_token"], data["user"]

# Ask question
def ask_question(token, question):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(
        f"{BASE_URL}/ask",
        json={"question": question},
        headers=headers
    )
    response.raise_for_status()
    return response.json()

# Usage
token, user = login("john.doe@klu.ac.in", "SecurePass123")
answer = ask_question(token, "What is the function of the retina?")
print(answer)
```

---

## Best Practices

### Security
1. **Never** store tokens in plain text on the client
2. Use HTTPS in production
3. Implement token refresh mechanism for better UX
4. Clear tokens on logout
5. Validate email on frontend before sending to API

### Error Handling
1. Always check response status codes
2. Display user-friendly error messages
3. Handle 401 errors by redirecting to login
4. Implement retry logic for network errors

### Performance
1. Cache user data locally
2. Implement request debouncing for search/autocomplete
3. Use streaming responses for better perceived performance
4. Implement offline support where applicable

---

## Support

For issues or questions, please contact the backend team or create an issue in the repository.

**API Documentation Version:** 1.0.0  
**Last Updated:** November 7, 2025
