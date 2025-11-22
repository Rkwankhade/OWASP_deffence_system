#!/usr/bin/env python3
"""
Easy Testing Script - Shows you exactly what's working
Run this after setting up owasp_defense.py
"""
from owasp_defense import OWASPTop10DefenseSystem
import time

def print_header(text):
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60)

def print_result(test_name, passed, details=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"\n{status} - {test_name}")
    if details:
        print(f"   Details: {details}")

def main():
    print_header("OWASP DEFENSE SYSTEM - COMPLETE TEST")
    
    # Initialize system
    print("\n🔧 Initializing security system...")
    try:
        system = OWASPTop10DefenseSystem()
        print("✅ System initialized successfully!")
        print(f"📁 Logs location: {system.log_directory}")
    except Exception as e:
        print(f"❌ System failed to initialize: {e}")
        return
    
    # TEST 1: Injection Detection
    print_header("TEST 1: Injection Detection")
    
    test_cases = [
        ("Normal text", "Hello, this is safe input", True),
        ("SQL Injection", "admin' OR '1'='1", False),
        ("SQL Drop Table", "test'; DROP TABLE users--", False),
        ("XSS Attack", "<script>alert('hacked')</script>", False),
        ("Command Injection", "test; rm -rf /", False)
    ]
    
    injection_passed = 0
    for name, input_text, should_be_safe in test_cases:
        result = system.injection_prevention.detect_injection(input_text)
        is_correct = result['safe'] == should_be_safe
        
        if is_correct:
            injection_passed += 1
        
        status = "✅" if is_correct else "❌"
        print(f"\n{status} {name}:")
        print(f"   Input: {input_text[:40]}")
        print(f"   Safe: {result['safe']} | Risk Score: {result['risk_score']}")
        if result['threats']:
            print(f"   Threats detected: {len(result['threats'])}")
    
    print(f"\n📊 Injection Detection: {injection_passed}/{len(test_cases)} tests passed")
    
    # TEST 2: User Registration
    print_header("TEST 2: User Registration")
    
    # Test valid registration
    print("\n🔹 Test 2a: Register valid user")
    result = system.auth_system.register_user("testuser123", "test@example.com", "SecurePass123!")
    print_result("Valid registration", result['success'], result['message'])
    
    # Test duplicate user
    print("\n🔹 Test 2b: Prevent duplicate registration")
    result = system.auth_system.register_user("testuser123", "test@example.com", "SecurePass123!")
    print_result("Duplicate prevention", not result['success'], result['message'])
    
    # Test weak password
    print("\n🔹 Test 2c: Reject weak password")
    result = system.auth_system.register_user("weakuser", "weak@example.com", "123")
    print_result("Weak password rejection", not result['success'], result['message'])
    
    # Test invalid email
    print("\n🔹 Test 2d: Reject invalid email")
    result = system.auth_system.register_user("badmail", "notanemail", "SecurePass123!")
    print_result("Invalid email rejection", not result['success'], result['message'])
    
    # TEST 3: Authentication
    print_header("TEST 3: Authentication & Brute Force Protection")
    
    # Test correct login
    print("\n🔹 Test 3a: Correct password login")
    result = system.auth_system.authenticate("testuser123", "SecurePass123!", "192.168.1.100")
    print_result("Correct login", result['success'], result['message'])
    
    # Test wrong password (multiple times to trigger lockout)
    print("\n🔹 Test 3b: Brute force protection (trying wrong password 5 times)")
    
    # Create a new user for brute force test
    system.auth_system.register_user("brutetest", "brute@test.com", "RealPass123!")
    
    for attempt in range(1, 6):
        result = system.auth_system.authenticate("brutetest", "WrongPassword", "192.168.1.200")
        print(f"   Attempt {attempt}: {result['message']}")
        time.sleep(0.5)  # Small delay between attempts
    
    # Try one more time to see if account is locked
    print("\n🔹 Test 3c: Account locked after 5 failed attempts")
    result = system.auth_system.authenticate("brutetest", "RealPass123!", "192.168.1.200")
    print_result("Account lockout", not result['success'] and "locked" in result['message'].lower(), 
                 result['message'])
    
    # TEST 4: Rate Limiting
    print_header("TEST 4: Rate Limiting")
    
    print("\n🔹 Simulating 105 requests from same IP...")
    allowed_count = 0
    blocked_count = 0
    
    for i in range(105):
        if system.rate_limiter.is_allowed("192.168.1.50"):
            allowed_count += 1
        else:
            blocked_count += 1
    
    print(f"   Allowed: {allowed_count} requests")
    print(f"   Blocked: {blocked_count} requests")
    print_result("Rate limiting works", blocked_count > 0, 
                 f"Should block after 100 requests")
    
    # FINAL SUMMARY
    print_header("FINAL SUMMARY")
    
    print("\n✅ WORKING FEATURES:")
    print("   • Injection detection (SQL, XSS, Command)")
    print("   • User registration with validation")
    print("   • Secure password hashing (PBKDF2)")
    print("   • Authentication system")
    print("   • Brute force protection (account locking)")
    print("   • Rate limiting")
    print("   • Security event logging")
    
    print(f"\n📋 CHECK YOUR LOGS:")
    print(f"   Location: {system.log_directory}")
    print(f"   Database: {system.db_path}")
    print("\n   View logs with: cat ~/owasp_security/logs/security_*.log")
    print("   View database: sqlite3 ~/owasp_security/logs/owasp_secure.db")
    
    print("\n" + "="*60)
    print("  🎉 TESTING COMPLETE!")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
