#!/bin/bash
cd /root/TokenLensLicesen
export DB_PATH=license_admin.db
export LICENSE_PRIVATE_KEY_PATH=keys/license_private.pem
export LICENSE_PUBLIC_KEY_PATH=keys/license_public.pem
export HOST=0.0.0.0
export PORT=8001
export ADMIN_TOKEN=admin-secret-token
exec /root/SpringStillness/venv/bin/python3 api_server.py
