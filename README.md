# TokenLens License Admin

公司内部授权管理系统，独立于客户侧 TokenLens 代码审计平台。

核心能力：

- Ed25519 私钥离线签发授权文件
- 授权台账管理
- 备注、吊销、恢复、删除、重下载
- 仅下发公钥到客户侧平台

启动：

```bash
pip install -r requirements.txt
export LICENSE_PRIVATE_KEY_PATH=./keys/license_private.pem
uvicorn app:app --host 0.0.0.0 --port 8001
```

初始化密钥：

```bash
python3 license_manager.py generate-keypair \
  --private-key-out ./keys/license_private.pem \
  --public-key-out ./keys/license_public.pem
```

默认账号：

- `admin / admin123`

首次登录后请立即修改。
