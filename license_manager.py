import argparse
import base64
import hashlib
import json
import os
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DEFAULT_PRODUCT = 'TokenLens'


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _b64url_decode(text: str) -> bytes:
    padding = '=' * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _parse_iso8601(text: str):
    if not text:
        return None
    return datetime.fromisoformat(text.strip().replace('Z', '+00:00'))


def _read_text_from_env_or_path(value_env: str, path_env: str) -> str:
    inline = os.getenv(value_env, '').strip()
    if inline:
        return inline
    path = os.getenv(path_env, '').strip()
    if path:
        return Path(path).read_text(encoding='utf-8').strip()
    return ''


def get_private_key() -> Ed25519PrivateKey:
    pem = _read_text_from_env_or_path('LICENSE_PRIVATE_KEY', 'LICENSE_PRIVATE_KEY_PATH')
    if not pem:
        raise RuntimeError('未配置 LICENSE_PRIVATE_KEY 或 LICENSE_PRIVATE_KEY_PATH')
    key = serialization.load_pem_private_key(pem.encode('utf-8'), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError('私钥类型不正确，当前仅支持 Ed25519')
    return key


def get_public_key() -> Ed25519PublicKey:
    pem = _read_text_from_env_or_path('LICENSE_PUBLIC_KEY', 'LICENSE_PUBLIC_KEY_PATH')
    if not pem:
        raise RuntimeError('未配置 LICENSE_PUBLIC_KEY 或 LICENSE_PUBLIC_KEY_PATH')
    key = serialization.load_pem_public_key(pem.encode('utf-8'))
    if not isinstance(key, Ed25519PublicKey):
        raise RuntimeError('公钥类型不正确，当前仅支持 Ed25519')
    return key


def generate_keypair(private_key_path: str, public_key_path: str):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('utf-8')
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(private_pem, encoding='utf-8')
    public_path.write_text(public_pem, encoding='utf-8')
    try:
        os.chmod(private_path, 0o600)
    except Exception:
        pass
    return str(private_path), str(public_path)


def get_machine_code() -> str:
    explicit = os.getenv('PRODUCT_INSTANCE_ID', '').strip()
    if explicit:
        return explicit
    source = f'{socket.gethostname()}::{uuid.getnode()}'
    return hashlib.sha256(source.encode('utf-8')).hexdigest()[:24]


def build_license_payload(customer: str, expires_at: str, product: str = DEFAULT_PRODUCT,
                          features=None, machine_code: str = '', metadata=None) -> dict:
    return {
        'product': product,
        'customer': customer.strip(),
        'issued_at': _iso_now(),
        'expires_at': expires_at.strip(),
        'features': features or [],
        'machine_code': machine_code.strip(),
        'metadata': metadata or {},
    }


def generate_license_token(payload: dict, private_key: Optional[Ed25519PrivateKey] = None) -> str:
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')
    encoded = _b64url_encode(body)
    signature = (private_key or get_private_key()).sign(encoded.encode('ascii'))
    return f'{encoded}.{_b64url_encode(signature)}'


def verify_license_token(token: str, public_key: Optional[Ed25519PublicKey] = None,
                         expected_product: str = DEFAULT_PRODUCT,
                         expected_machine_code: Optional[str] = None) -> dict:
    token = (token or '').strip()
    if not token:
        return {'valid': False, 'state': 'missing', 'message': '未导入授权文件'}
    try:
        encoded, signature = token.split('.', 1)
    except ValueError:
        return {'valid': False, 'state': 'format_error', 'message': '授权文件令牌格式不正确'}
    try:
        (public_key or get_public_key()).verify(_b64url_decode(signature), encoded.encode('ascii'))
    except InvalidSignature:
        return {'valid': False, 'state': 'invalid_signature', 'message': '授权文件签名校验失败'}
    try:
        payload = json.loads(_b64url_decode(encoded).decode('utf-8'))
    except Exception:
        return {'valid': False, 'state': 'payload_error', 'message': '授权文件内容无法解析'}
    if payload.get('product') != expected_product:
        return {'valid': False, 'state': 'product_mismatch', 'message': '授权产品不匹配', 'payload': payload}
    expires_at = _parse_iso8601(payload.get('expires_at', ''))
    if not expires_at:
        return {'valid': False, 'state': 'expires_invalid', 'message': '授权过期时间无效', 'payload': payload}
    if expires_at <= datetime.now(timezone.utc):
        return {'valid': False, 'state': 'expired', 'message': '授权已过期', 'payload': payload}
    bound_machine = (payload.get('machine_code') or '').strip()
    if bound_machine and expected_machine_code and bound_machine != expected_machine_code:
        return {'valid': False, 'state': 'machine_mismatch', 'message': '授权机器码不匹配', 'payload': payload}
    return {'valid': True, 'state': 'valid', 'message': '授权校验通过', 'payload': payload}


def load_license_file_content(text: str) -> str:
    text = (text or '').strip()
    if not text:
        raise ValueError('授权文件内容为空')
    data = json.loads(text)
    token = (data.get('license_token') or '').strip()
    if not token:
        raise ValueError('授权文件中未找到 license_token')
    return token


def load_machine_code(text: str) -> str:
    text = (text or '').strip()
    if not text:
        return ''
    if not text.startswith('{'):
        return text
    data = json.loads(text)
    machine_code = (data.get('machine_code') or '').strip()
    if not machine_code:
        raise ValueError('机器码文件中未找到 machine_code')
    return machine_code


def _build_parser():
    parser = argparse.ArgumentParser(description='TokenLens License Admin Tool')
    sub = parser.add_subparsers(dest='command', required=True)
    keygen = sub.add_parser('generate-keypair')
    keygen.add_argument('--private-key-out', default='license_private.pem')
    keygen.add_argument('--public-key-out', default='license_public.pem')
    gen = sub.add_parser('generate-file')
    gen.add_argument('--customer', required=True)
    gen.add_argument('--expires-at', required=True)
    gen.add_argument('--machine-code', required=True)
    gen.add_argument('--feature', action='append', default=[])
    gen.add_argument('--product', default=DEFAULT_PRODUCT)
    gen.add_argument('--metadata', default='{}')
    gen.add_argument('--output', default='license.json')
    verify = sub.add_parser('verify-file')
    verify.add_argument('--license-file', required=True)
    verify.add_argument('--machine-code', default='')
    verify.add_argument('--product', default=DEFAULT_PRODUCT)
    return parser


def main():
    args = _build_parser().parse_args()
    if args.command == 'generate-keypair':
        print(json.dumps(dict(zip(['private_key_path', 'public_key_path'], generate_keypair(args.private_key_out, args.public_key_out))), ensure_ascii=False, indent=2))
        return
    if args.command == 'generate-file':
        payload = build_license_payload(args.customer, args.expires_at, product=args.product, features=args.feature, machine_code=args.machine_code, metadata=json.loads(args.metadata or '{}'))
        out = {**payload, 'license_token': generate_license_token(payload)}
        Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
        print(args.output)
        return
    text = Path(args.license_file).read_text(encoding='utf-8')
    token = load_license_file_content(text)
    print(json.dumps(verify_license_token(token, expected_product=args.product, expected_machine_code=args.machine_code or None), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
