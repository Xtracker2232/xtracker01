#!/bin/bash
# Xtracker — Script d'installation VPS Ubuntu
# Usage : bash install.sh

echo "=== Xtracker Installation ==="

# Dépendances système
apt update -y
apt install -y python3 python3-pip python3-venv postgresql postgresql-contrib nginx certbot python3-certbot-nginx

# Créer venv
python3 -m venv /opt/xtracker/venv
source /opt/xtracker/venv/bin/activate

# Installer dépendances Python
pip install fastapi uvicorn psycopg2-binary "python-jose[cryptography]" "passlib[bcrypt]" stripe httpx python-multipart

# PostgreSQL
sudo -u postgres psql -c "CREATE USER xtracker WITH PASSWORD 'ChangeThisPassword123';"
sudo -u postgres psql -c "CREATE DATABASE xtracker OWNER xtracker;"

# Service systemd
cat > /etc/systemd/system/xtracker.service << 'SERVICE'
[Unit]
Description=Xtracker API
After=network.target postgresql.service

[Service]
User=root
WorkingDirectory=/opt/xtracker
Environment="DATABASE_URL=postgresql://xtracker:ChangeThisPassword123@localhost/xtracker"
Environment="SECRET_KEY=CHANGEZ_MOI_32_CHARS_MINIMUM"
Environment="STRIPE_SECRET=sk_live_VOTRE_CLE"
Environment="STRIPE_WEBHOOK=whsec_VOTRE_WEBHOOK"
ExecStart=/opt/xtracker/venv/bin/uvicorn app:app --host 0.0.0.0 --port 8080
Restart=always

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable xtracker
systemctl start xtracker

# Nginx
cat > /etc/nginx/sites-available/xtracker << 'NGINX'
server {
    listen 80;
    server_name VOTRE_DOMAINE.COM;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
NGINX

ln -s /etc/nginx/sites-available/xtracker /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx

echo ""
echo "=== Installation terminée ==="
echo "Editez /etc/systemd/system/xtracker.service pour vos clés"
echo "Puis : systemctl restart xtracker"
echo "SSL  : certbot --nginx -d VOTRE_DOMAINE.COM"