# OWASP Top 10 Defense System

A comprehensive security system implementing OWASP Top 10 protections.

## Features
- SQL Injection Prevention
- XSS Attack Detection
- Command Injection Prevention
- Secure Password Hashing (PBKDF2)
- Brute Force Protection (Account Locking)
- Rate Limiting
- Security Event Logging

## Installation
```bash
git clone https://github.com/YOUR_USERNAME/owasp-defense-system.git
cd owasp-defense-system
python3 owasp_defense.py
```

## Testing
```bash
python3 test_script.py
```

## Requirements
- Python 3.x
- SQLite3

## Security Features Tested
✅ Injection Detection (SQL, XSS, Command)
✅ User Registration with Validation
✅ Authentication System
✅ Account Lockout after Failed Attempts
✅ Rate Limiting (100 requests/minute)
