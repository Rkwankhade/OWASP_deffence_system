#!/usr/bin/env python3
"""
Enhanced OWASP Defense System
Compatible with Flask integration
Improved security practices for production use
"""
import os
import sqlite3
import re
import logging
from hashlib import sha256, pbkdf2_hmac
from datetime import datetime
import secrets

class OWASPTop10DefenseSystem:
    def __init__(self):
        # Secure logging setup
        self.log_directory = os.path.expanduser("~/owasp_security/logs")
        os.makedirs(self.log_directory, exist_ok=True)
        
        # Configure logging
        log_file = os.path.join(self.log_directory, f"security_{datetime.now().strftime('%Y%m%d')}.log")
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Database with secure path
        self.db_path = os.path.join(self.log_directory, "owasp_secure.db")
        self._init_db()
        
        # Initialize security modules
        self.injection_prevention = InjectionPrevention(self.logger)
        self.auth_system = AuthSystem(self.db_path, self.logger)
        self.rate_limiter = RateLimiter(self.logger)
        
        self.logger.info("OWASP Defense System initialized")
    
    def _init_db(self):
        """Initialize secure database with proper schema"""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Users table with additional security fields
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """)
        
        # Security events log
        cur.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            username TEXT,
            ip_address TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        conn.commit()
        conn.close()

# -------------------------
# Enhanced Injection Prevention
# -------------------------
class InjectionPrevention:
    def __init__(self, logger):
        self.logger = logger
        
        # Comprehensive threat patterns
        self.sql_patterns = [
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bDROP\b.*\bTABLE\b)",
            r"(\bINSERT\b.*\bINTO\b)",
            r"(--[^\n]*)",
            r"(/\*.*?\*/)",
            r"(\bEXEC\b|\bEXECUTE\b)",
            r"(;.*\b(DROP|DELETE|UPDATE|INSERT)\b)"
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe",
            r"eval\s*\("
        ]
    
    def detect_injection(self, user_input, input_type="general"):
        """
        Detect various injection attempts
        Returns: dict with safety status and details
        """
        if not user_input:
            return {"safe": True, "risk_score": 0, "threats": []}
        
        threats = []
        risk_score = 0
        
        # SQL Injection detection
        for pattern in self.sql_patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                threats.append(f"SQL Injection: {pattern}")
                risk_score += 30
        
        # XSS detection
        for pattern in self.xss_patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                threats.append(f"XSS Attack: {pattern}")
                risk_score += 25
        
        # Command injection
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '>', '<']
        for char in dangerous_chars:
            if char in user_input:
                threats.append(f"Command Injection: '{char}'")
                risk_score += 15
        
        is_safe = risk_score == 0
        
        if not is_safe:
            self.logger.warning(f"Injection detected - Risk: {risk_score} - Input: {user_input[:50]}")
        
        return {
            "safe": is_safe,
            "risk_score": min(risk_score, 100),
            "threats": threats,
            "input_snippet": user_input[:100]
        }
    
    def sanitize_input(self, user_input):
        """Basic input sanitization"""
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>\'";`]', '', user_input)
        return sanitized.strip()

# -------------------------
# Enhanced Auth System
# -------------------------
class AuthSystem:
    def __init__(self, db_path, logger):
        self.db_path = db_path
        self.logger = logger
        self.max_failed_attempts = 5
    
    def hash_password(self, password, salt=None):
        """Secure password hashing using PBKDF2"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 with SHA256 (more secure than plain SHA256)
        pwd_hash = pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return pwd_hash.hex(), salt
    
    def register_user(self, username, email, password):
        """Register new user with secure password storage"""
        conn = None
        try:
            # Validate inputs
            if len(password) < 8:
                return {"success": False, "message": "Password must be at least 8 characters"}
            
            if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
                return {"success": False, "message": "Invalid email format"}
            
            pwd_hash, salt = self.hash_password(password)
            
            conn = sqlite3.connect(self.db_path, timeout=10)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)",
                (username, email, pwd_hash, salt)
            )
            conn.commit()
            
            self.logger.info(f"New user registered: {username}")
            return {"success": True, "message": "User registered successfully"}
            
        except sqlite3.IntegrityError:
            return {"success": False, "message": "Username or email already exists"}
        except Exception as e:
            self.logger.error(f"Registration error: {str(e)}")
            return {"success": False, "message": "Registration failed"}
        finally:
            if conn:
                conn.close()
    
    def authenticate(self, username, password, ip=None):
        """Authenticate user with brute force protection"""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.isolation_level = None  # Autocommit mode
        cur = conn.cursor()
        
        try:
            # Check if account is locked
            cur.execute(
                "SELECT password_hash, salt, failed_login_attempts, account_locked FROM users WHERE username=?",
                (username,)
            )
            row = cur.fetchone()
            
            if not row:
                self._log_security_event(cur, "failed_login", username, ip, "User not found")
                return {"success": False, "message": "Invalid credentials"}
            
            pwd_hash, salt, failed_attempts, locked = row
            
            # Check if account is locked
            if locked:
                return {"success": False, "message": "Account locked. Contact administrator."}
            
            # Verify password
            computed_hash, _ = self.hash_password(password, salt)
            
            if computed_hash == pwd_hash:
                # Successful login - reset failed attempts
                cur.execute(
                    "UPDATE users SET failed_login_attempts=0, last_login=? WHERE username=?",
                    (datetime.now(), username)
                )
                self._log_security_event(cur, "successful_login", username, ip, "Login successful")
                
                self.logger.info(f"Successful login: {username}")
                return {"success": True, "message": "Authenticated", "username": username}
            else:
                # Failed login - increment counter
                failed_attempts += 1
                locked = 1 if failed_attempts >= self.max_failed_attempts else 0
                
                cur.execute(
                    "UPDATE users SET failed_login_attempts=?, account_locked=? WHERE username=?",
                    (failed_attempts, locked, username)
                )
                self._log_security_event(cur, "failed_login", username, ip, f"Attempt {failed_attempts}")
                
                self.logger.warning(f"Failed login attempt {failed_attempts} for {username}")
                
                if locked:
                    return {"success": False, "message": "Account locked due to multiple failed attempts"}
                return {"success": False, "message": "Invalid credentials"}
        
        finally:
            conn.close()
    
    def _log_security_event(self, cur, event_type, username, ip, details):
        """Log security events to database"""
        cur.execute(
            "INSERT INTO security_events (event_type, username, ip_address, details) VALUES (?, ?, ?, ?)",
            (event_type, username, ip, details)
        )

# -------------------------
# Rate Limiter
# -------------------------
class RateLimiter:
    def __init__(self, logger):
        self.logger = logger
        self.requests = {}  # ip -> [timestamps]
        self.max_requests = 100
        self.window_seconds = 60
    
    def is_allowed(self, ip_address):
        """Check if request is within rate limit"""
        now = datetime.now().timestamp()
        
        if ip_address not in self.requests:
            self.requests[ip_address] = []
        
        # Remove old timestamps
        self.requests[ip_address] = [
            ts for ts in self.requests[ip_address]
            if now - ts < self.window_seconds
        ]
        
        # Check limit
        if len(self.requests[ip_address]) >= self.max_requests:
            self.logger.warning(f"Rate limit exceeded for {ip_address}")
            return False
        
        self.requests[ip_address].append(now)
        return True

# -------------------------
# Demo Usage
# -------------------------
if __name__ == "__main__":
    system = OWASPTop10DefenseSystem()
    
    print("=== OWASP Defense System Demo ===\n")
    
    # Test injection detection
    print("1. Testing Injection Detection:")
    test_inputs = [
        "normal input",
        "SELECT * FROM users--",
        "<script>alert('xss')</script>",
        "test'; DROP TABLE users--"
    ]
    
    for inp in test_inputs:
        result = system.injection_prevention.detect_injection(inp)
        print(f"Input: {inp[:30]}")
        print(f"Safe: {result['safe']}, Risk: {result['risk_score']}\n")
    
    # Test user registration
    print("\n2. Testing User Registration:")
    reg_result = system.auth_system.register_user("testuser", "test@example.com", "SecurePass123!")
    print(f"Registration: {reg_result['message']}")
    
    # Test authentication
    print("\n3. Testing Authentication:")
    auth_result = system.auth_system.authenticate("testuser", "SecurePass123!", "127.0.0.1")
    print(f"Auth: {auth_result['message']}")
    
    # Test wrong password
    auth_result = system.auth_system.authenticate("testuser", "WrongPass", "127.0.0.1")
    print(f"Wrong password: {auth_result['message']}")
    
    print("\n=== Demo Complete ===")
    print(f"Check logs at: {system.log_directory}")
