# app.py
from flask import Flask, jsonify, request
from keycloak import KeycloakOpenID
from functools import wraps
import os

app = Flask(__name__)

# 1. KONFIGURASI KEYCLOAK
keycloak_openid = KeycloakOpenID(
    server_url=os.environ.get('KC_REALM_URL').replace('/realms/ZeroTrustRealm', ''),
    realm_name='ZeroTrustRealm',
    client_id=os.environ.get('KC_CLIENT_ID'),
    client_secret_key=os.environ.get('KC_CLIENT_SECRET'),
)

# 2. FUNGSI DECORATOR UNTUK VERIFIKASI TOKEN & RBAC
def require_role(role_name):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({"msg": "Zero Trust Policy: Token Missing"}), 401

            try:
                # Verifikasi Eksplisit (Always Verify)
                token = auth_header.split(" ")[1]
                # Menggunakan Keycloak untuk memverifikasi token
                token_info = keycloak_openid.introspect(token) 
                
                if not token_info.get('active'):
                    return jsonify({"msg": "Zero Trust Policy: Invalid Token"}), 401
                
                # Least Privilege Access (RBAC Check)
                realm_access = token_info.get('realm_access', {})
                roles = realm_access.get('roles', [])
                
                if role_name not in roles:
                    # Menolak akses karena tidak memiliki hak istimewa yang cukup
                    return jsonify({"msg": f"Zero Trust Policy: Access Denied. Requires role: {role_name}"}), 403
                
                # Jika token valid dan role sesuai, izinkan akses
                return f(*args, **kwargs)
            
            except Exception as e:
                print(f"Token verification error: {e}")
                return jsonify({"msg": "Zero Trust Policy: Token Verification Failed"}), 401
        return decorated
    return decorator

# 3. ENDPOINTS DENGAN RBAC YANG BERBEDA
# Endpoint Publik (Hanya perlu autentikasi)
@app.route('/api/data/public')
@require_role('viewer') # Kita paksa minimal role viewer
def public_data():
    return jsonify({"data": "Data publik berhasil diakses (Minimal Viewer Role)"})

# Endpoint Sensitif (Hanya Role Admin)
@app.route('/api/data/admin')
@require_role('admin')
def admin_data():
    return jsonify({"data": "Data ADMIN SENSITIF berhasil diakses (Hanya Admin)"})

# Endpoint Viewer (Hanya Role Viewer/Admin)
@app.route('/api/data/viewer')
@require_role('viewer')
def viewer_data():
    return jsonify({"data": "Data viewer berhasil diakses (Role Viewer/Admin)"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)