# TokenLens License Server

独立的License授权管理服务，与SpringStillness代码审计平台完全分离。

## 功能特性

- 🔐 **Ed25519数字签名** - 使用现代加密算法保护授权文件
- 🔑 **API Key认证** - 客户端通过API Key进行身份验证
- 🖥️ **机器码绑定** - 授权与特定机器绑定，防止转移
- 📅 **有效期管理** - 支持授权过期时间控制
- 📝 **授权记录** - 完整的数据库记录管理
- 🌐 **REST API** - 基于FastAPI的现代API设计

## 快速开始

### 安装依赖

```bash
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn python-multipart cryptography
```

### 启动服务

```bash
# 复制环境配置模板
cp .env.example .env

# 启动服务器
./run_server.sh
```

服务将运行在 http://localhost:8001

## API接口

### 1. 注册API客户端
```bash
POST /api/v1/clients/register
Header: X-Admin-Token: <admin-token>
Body: {
  "client_name": "My Application",
  "allowed_products": ["SpringStillness"]
}

Response: {
  "client_id": "client_xxx",
  "api_key": "xxx-xxx-xxx",  // 仅显示一次，请妥善保存
  "client_name": "My Application",
  "allowed_products": ["SpringStillness"]
}
```

### 2. 生成License
```bash
POST /api/v1/generate
Header: X-Admin-Token: <admin-token>
Body: {
  "customer": "Customer Name",
  "machine_code": "abc123...",
  "expires_at": "2027-12-31T23:59:59Z",
  "product": "SpringStillness",
  "features": ["code_audit", "sbom_generator"],
  "metadata": {"tier": "enterprise"}
}

Response: {
  "success": true,
  "record_id": 1,
  "license_token": "...",
  "payload": {...}
}
```

### 3. 验证License
```bash
POST /api/v1/verify
Header: X-API-Key: <api-key>
Body: {
  "license_token": "...",
  "machine_code": "abc123...",
  "product": "SpringStillness"
}

Response: {
  "valid": true|false,
  "state": "valid|machine_mismatch|expired|...",
  "message": "...",
  "payload": {...}  // License内容
}
```

## 与SpringStillness集成

SpringStillness代码审计平台通过`license_client.py`与本服务通信：

1. 审计平台向License服务注册获取API Key
2. License服务使用私钥签名生成授权文件
3. 审计平台持有本地License文件和公钥
4. 审计平台通过API验证授权

## 安全设计

- ✅ 私钥仅保存在授权服务端 (`keys/license_private.pem`)
- ✅ 公钥分发给审计平台客户端
- ✅ API Key用于客户端身份认证
- ✅ 机器码绑定防止License转移
- ✅ Ed25519数字签名防止授权文件篡改

## 密钥生成

如需生成新的密钥对：

```bash
python3 -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# 保存私钥
with open('keys/license_private.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# 保存公钥
with open('keys/license_public.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
"
```

## 注意事项

⚠️ **生产环境安全警告**
- `keys/license_private.pem` 是私密文件，不应提交到版本控制
- `.env` 包含敏感配置，请使用 `.env.example` 创建本地配置
- 定期轮换 `ADMIN_TOKEN` 和 API Keys

## 技术栈

- Python 3.12+
- FastAPI 0.110+
- Ed25519 数字签名
- SQLite 数据库

## License

MIT License - 开源软件
