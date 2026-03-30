#!/usr/bin/env python3
"""Generate Ed25519 keypair for License signing"""
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def generate_keypair(private_key_path='keys/license_private.pem', 
                     public_key_path='keys/license_public.pem'):
    """Generate a new Ed25519 keypair for license signing"""
    print("Generating Ed25519 keypair...")
    
    # Generate private key
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Ensure keys directory exists
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)
    
    # Write keys
    with open(private_key_path, 'wb') as f:
        f.write(private_pem)
    
    with open(public_key_path, 'wb') as f:
        f.write(public_pem)
    
    # Set secure permissions for private key
    os.chmod(private_key_path, 0o600)
    os.chmod(public_key_path, 0o644)
    
    print(f"✓ Private key saved to: {private_key_path}")
    print(f"✓ Public key saved to: {public_key_path}")
    print("\n⚠️  IMPORTANT: Keep your private key secure! Do not commit it to version control.")
    print()

if __name__ == '__main__':
    generate_keypair()
