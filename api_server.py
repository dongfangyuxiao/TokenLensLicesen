"""
TokenLens License API Server
独立的License授权服务，提供授权生成和校验API
"""
import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import sqlite3

# Import license manager functions
import license_manager as lm
db = __import__('database')

app = FastAPI(title='TokenLens License API Server', version='1.0.0')

# API Key authentication
API_KEYS = {}  # 存储已注册的审计平台API密钥

def init_api_keys_db():
    """初始化API密钥表"""
    conn = db.get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS api_clients (
        client_id TEXT PRIMARY KEY,
        client_name TEXT NOT NULL,
        api_key_hash TEXT NOT NULL,
        api_key_salt TEXT NOT NULL,
        allowed_products TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        is_active INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX IF NOT EXISTS idx_api_clients_key ON api_clients(api_key_hash);
    """)
    conn.commit()
    return conn

def hash_api_key(api_key: str, salt: Optional[str] = None):
    """哈希API密钥"""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', api_key.encode('utf-8'), salt.encode('utf-8'), 100000)
    return dk.hex(), salt

def verify_api_key(api_key: str) -> Optional[dict]:
    """验证API密钥"""
    conn = db.get_conn()
    cursor = conn.execute("SELECT * FROM api_clients WHERE is_active=1")
    for row in cursor:
        stored_hash, salt = row['api_key_hash'], row['api_key_salt']
        computed_hash, _ = hash_api_key(api_key, salt)
        if computed_hash == stored_hash:
            # 更新最后使用时间
            conn.execute(
                "UPDATE api_clients SET last_used_at=? WHERE client_id=?",
                (datetime.now().isoformat(), row['client_id'])
            )
            conn.commit()
            return {
                'client_id': row['client_id'],
                'client_name': row['client_name'],
                'allowed_products': json.loads(row['allowed_products'] or '[]')
            }
    return None

def require_api_key(x_api_key: str = Header(None, alias='X-API-Key')):
    """API Key依赖"""
    if not x_api_key:
        raise HTTPException(401, 'Missing API Key header')
    client = verify_api_key(x_api_key)
    if not client:
        raise HTTPException(401, 'Invalid API Key')
    return client

# 请求模型
class LicenseVerifyRequest(BaseModel):
    license_token: str
    machine_code: Optional[str] = None
    product: Optional[str] = None

class LicenseGenerateRequest(BaseModel):
    customer: str
    machine_code: str
    expires_at: str  # ISO8601格式
    product: str = 'SpringStillness'
    features: List[str] = []
    metadata: dict = {}

class ApiClientRegisterRequest(BaseModel):
    client_name: str
    allowed_products: List[str] = ['SpringStillness']

class ApiClientResponse(BaseModel):
    client_id: str
    api_key: str  # 仅创建时返回一次
    client_name: str
    allowed_products: List[str]

# 启动时的初始化
@app.on_event('startup')
async def startup_event():
    db.init_db()
    init_api_keys_db()
    print("License API Server started")

@app.get('/')
def root():
    return {
        'service': 'TokenLens License API Server',
        'version': '1.0.0',
        'endpoints': {
            'verify': '/api/v1/verify (POST)',
            'generate': '/api/v1/generate (POST) - Admin only',
            'register': '/api/v1/clients/register (POST) - Admin only',
        }
    }

@app.post('/api/v1/verify')
def verify_license(
    request: LicenseVerifyRequest,
    client: dict = Depends(require_api_key)
):
    """
    校验License授权
    
    请求体:
    - license_token: 授权令牌字符串
    - machine_code: (可选) 机器码用于绑定校验
    - product: (可选) 期望的产品名称，默认使用客户端配置
    """
    expected_product = request.product or (client['allowed_products'][0] if client['allowed_products'] else 'SpringStillness')
    
    # 检查客户端是否有权限校验该产品的License
    if client['allowed_products'] and expected_product not in client['allowed_products']:
        raise HTTPException(403, f'Client not authorized for product: {expected_product}')
    
    # 使用公钥校验License
    try:
        public_key = lm.get_public_key()
        result = lm.verify_license_token(
            request.license_token,
            public_key=public_key,
            expected_product=expected_product,
            expected_machine_code=request.machine_code
        )
        
        # 添加审计信息
        result['verified_by'] = client['client_id']
        result['verified_at'] = datetime.now(timezone.utc).isoformat()
        
        return result
        
    except Exception as e:
        return {
            'valid': False,
            'state': 'verify_error',
            'message': f'License verification failed: {str(e)}'
        }

@app.post('/api/v1/generate')
def generate_license(
    request: LicenseGenerateRequest,
    admin_token: str = Header(None, alias='X-Admin-Token')
):
    """
    生成新的License授权（仅管理员）
    
    请求体:
    - customer: 客户名称
    - machine_code: 绑定的机器码
    - expires_at: 过期时间 (ISO8601格式)
    - product: 产品名称
    - features: 授权功能列表
    - metadata: 扩展元数据
    """
    # 简单的管理员token验证（生产环境应使用更安全的认证）
    expected_admin_token = os.getenv('ADMIN_TOKEN', 'admin-secret-token')
    if admin_token != expected_admin_token:
        raise HTTPException(401, 'Invalid admin token')
    
    try:
        payload = lm.build_license_payload(
            customer=request.customer,
            expires_at=request.expires_at,
            product=request.product,
            features=request.features,
            machine_code=request.machine_code,
            metadata=request.metadata
        )
        
        private_key = lm.get_private_key()
        license_token = lm.generate_license_token(payload, private_key=private_key)
        
        # 记录到数据库
        record_id = db.create_license_record(
            customer=request.customer,
            product=request.product,
            machine_code=request.machine_code,
            expires_at=request.expires_at,
            features=request.features,
            metadata=request.metadata,
            license_token=license_token,
            created_by='api_admin',
            remark='Generated via API'
        )
        
        return {
            'success': True,
            'record_id': record_id,
            'license_token': license_token,
            'payload': payload
        }
        
    except Exception as e:
        raise HTTPException(500, f'Failed to generate license: {str(e)}')

@app.post('/api/v1/clients/register', response_model=ApiClientResponse)
def register_client(
    request: ApiClientRegisterRequest,
    admin_token: str = Header(None, alias='X-Admin-Token')
):
    """
    注册新的API客户端（审计平台）
    
    返回的api_key只显示一次，请妥善保存。
    """
    expected_admin_token = os.getenv('ADMIN_TOKEN', 'admin-secret-token')
    if admin_token != expected_admin_token:
        raise HTTPException(401, 'Invalid admin token')
    
    client_id = f"client_{secrets.token_hex(8)}"
    api_key = secrets.token_urlsafe(32)
    api_key_hash, salt = hash_api_key(api_key)
    
    conn = db.get_conn()
    conn.execute(
        """INSERT INTO api_clients 
           (client_id, client_name, api_key_hash, api_key_salt, allowed_products, created_at, is_active)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (client_id, request.client_name, api_key_hash, salt, 
         json.dumps(request.allowed_products), datetime.now().isoformat(), 1)
    )
    conn.commit()
    
    return ApiClientResponse(
        client_id=client_id,
        api_key=api_key,
        client_name=request.client_name,
        allowed_products=request.allowed_products
    )

@app.get('/api/v1/clients')
def list_clients(
    admin_token: str = Header(None, alias='X-Admin-Token')
):
    """列出所有注册的API客户端（仅管理员）"""
    expected_admin_token = os.getenv('ADMIN_TOKEN', 'admin-secret-token')
    if admin_token != expected_admin_token:
        raise HTTPException(401, 'Invalid admin token')
    
    conn = db.get_conn()
    rows = conn.execute(
        "SELECT client_id, client_name, allowed_products, created_at, last_used_at, is_active FROM api_clients"
    ).fetchall()
    
    return [
        {
            'client_id': r['client_id'],
            'client_name': r['client_name'],
            'allowed_products': json.loads(r['allowed_products'] or '[]'),
            'created_at': r['created_at'],
            'last_used_at': r['last_used_at'],
            'is_active': bool(r['is_active'])
        }
        for r in rows
    ]


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host=os.getenv('HOST', '0.0.0.0'), port=int(os.getenv('PORT', 8001)))
