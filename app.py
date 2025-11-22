from flask import Flask, request, jsonify
from owasp_defense import OWASPTop10DefenseSystem

app = Flask(__name__)
defense = OWASPTop10DefenseSystem()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    result = defense.auth_system.register_user(
        data['username'], 
        data['email'], 
        data['password']
    )
    return jsonify(result)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    ip = request.remote_addr
    
    # Check rate limit
    if not defense.rate_limiter.is_allowed(ip):
        return jsonify({"success": False, "message": "Too many requests"}), 429
    
    # Check for injection
    injection_check = defense.injection_prevention.detect_injection(data['username'])
    if not injection_check['safe']:
        return jsonify({"success": False, "message": "Invalid input detected"}), 400
    
    result = defense.auth_system.authenticate(
        data['username'],
        data['password'],
        ip
    )
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
