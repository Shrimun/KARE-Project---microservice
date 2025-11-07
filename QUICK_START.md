# Quick Start Guide for Frontend Developers

## Base URL
```
http://localhost:8000
```
(Update to your production URL when deployed)

---

## Authentication Flow

### 1️⃣ User Signup
```javascript
const signup = async (userData) => {
    const response = await fetch('http://localhost:8000/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: "John Doe",
            email: "john.doe@klu.ac.in",  // Must be @klu.ac.in
            password: "SecurePass123",     // Min 8 chars, 1 uppercase, 1 lowercase, 1 digit
            department: "Computer Science",
            phone_number: "+919876543210"  // Indian format
        })
    });
    
    const data = await response.json();
    // Store token: localStorage.setItem('token', data.access_token);
    return data;
};
```

### 2️⃣ User Login
```javascript
const login = async (email, password) => {
    const response = await fetch('http://localhost:8000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });
    
    const data = await response.json();
    // Store token: localStorage.setItem('token', data.access_token);
    return data;
};
```

### 3️⃣ Get Current User
```javascript
const getCurrentUser = async () => {
    const token = localStorage.getItem('token');
    
    const response = await fetch('http://localhost:8000/me', {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    
    return await response.json();
};
```

### 4️⃣ Ask Question (Protected Endpoint)
```javascript
const askQuestion = async (question) => {
    const token = localStorage.getItem('token');
    
    const response = await fetch('http://localhost:8000/ask', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ question })
    });
    
    return await response.json();
};
```

### 5️⃣ Logout
```javascript
const logout = async () => {
    const token = localStorage.getItem('token');
    
    await fetch('http://localhost:8000/logout', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    
    // Clear local storage
    localStorage.removeItem('token');
};
```

---

## React Native Example (with AsyncStorage)

```javascript
import AsyncStorage from '@react-native-async-storage/async-storage';

// Login
const login = async (email, password) => {
    const response = await fetch('http://localhost:8000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });
    
    const data = await response.json();
    await AsyncStorage.setItem('token', data.access_token);
    return data;
};

// Make authenticated request
const askQuestion = async (question) => {
    const token = await AsyncStorage.getItem('token');
    
    const response = await fetch('http://localhost:8000/ask', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ question })
    });
    
    return await response.json();
};
```

---

## Error Handling

```javascript
const handleApiCall = async (apiFunction) => {
    try {
        const response = await apiFunction();
        return { success: true, data: response };
    } catch (error) {
        if (error.response?.status === 401) {
            // Token expired or invalid - redirect to login
            localStorage.removeItem('token');
            window.location.href = '/login';
        } else if (error.response?.status === 422) {
            // Validation error
            return { success: false, error: 'Invalid input data' };
        } else {
            return { success: false, error: 'An error occurred' };
        }
    }
};
```

---

## Validation Rules

### Email
- Must end with `@klu.ac.in`
- Format: `username@klu.ac.in`

### Password
- Minimum 8 characters
- At least 1 uppercase letter (A-Z)
- At least 1 lowercase letter (a-z)
- At least 1 digit (0-9)

### Phone Number
- Formats accepted:
  - `9876543210` (10 digits)
  - `+919876543210` (with country code)
  - `+91 9876543210` (with spaces)

---

## Response Formats

### Success Response (Signup/Login)
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "user": {
        "user_id": "abc123",
        "name": "John Doe",
        "email": "john.doe@klu.ac.in",
        "department": "Computer Science",
        "phone_number": "+919876543210",
        "created_at": "2025-11-07T15:55:40.455000"
    }
}
```

### Error Response
```json
{
    "error": {
        "status": 400,
        "message": "Email domain not allowed. Only @klu.ac.in emails are accepted.",
        "details": null
    }
}
```

---

## Common HTTP Status Codes

| Code | Meaning | Action |
|------|---------|--------|
| 200 | Success | Continue normally |
| 401 | Unauthorized | Token expired/invalid - redirect to login |
| 422 | Validation Error | Show validation errors to user |
| 500 | Server Error | Show generic error message |

---

## Token Management Best Practices

### Web (React/Vue/Angular)
```javascript
// Store token after login
localStorage.setItem('token', data.access_token);

// Include in all protected requests
headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }

// Remove on logout
localStorage.removeItem('token');
```

### Mobile (React Native)
```javascript
// Store token
await AsyncStorage.setItem('token', data.access_token);

// Retrieve token
const token = await AsyncStorage.getItem('token');

// Remove on logout
await AsyncStorage.removeItem('token');
```

---

## Testing with cURL (for debugging)

### Signup
```bash
curl -X POST "http://localhost:8000/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@klu.ac.in",
    "password": "SecurePass123",
    "department": "CS",
    "phone_number": "+919876543210"
  }'
```

### Login
```bash
curl -X POST "http://localhost:8000/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@klu.ac.in",
    "password": "SecurePass123"
  }'
```

### Get Current User
```bash
curl -X GET "http://localhost:8000/me" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

---

## Need More Help?

- Full API Documentation: `docs/API_DOCUMENTATION.md`
- Setup Guide: `SETUP_GUIDE.md`
- Test Results: `TEST_RESULTS.md`

---

**Happy Coding! 🚀**
