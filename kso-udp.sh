
#!/bin/bash
# ZIVPN UDP Server + Web UI (Myanmar) - No Key Version
# Author mix: Zahid Islam + UPK + DEV-U PHOE KAUNT
# Features: No Key Gate, Auto Port Forwarding, Flask Web UI, User Sync

set -euo pipefail

# ===== Pretty Colors =====
B="\e[1;34m"; G="\e[1;32m"; Y="\e[1;33m"; R="\e[1;31m"; C="\e[1;36m"; M="\e[1;35m"; Z="\e[0m"
LINE="${B}────────────────────────────────────────────────────────${Z}"
say(){ echo -e "$1"; }

echo -e "\n$LINE\n${G}🌟 ZIVPN UDP Server + Web UI (Keyless Version)${Z}\n$LINE"

# ===== Root check =====
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${R}ဤ script ကို root အဖြစ် chạy ရပါမယ် (sudo -i)${Z}"; exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# ===== apt guards =====
wait_for_apt() {
  echo -e "${Y}⏳ apt ပိတ်မချင်း စောင့်နေပါတယ်...${Z}"
  for _ in $(seq 1 60); do
    if pgrep -x apt-get >/dev/null || pgrep -x apt >/dev/null || pgrep -f 'apt.systemd.daily' >/dev/null || pgrep -x unattended-upgrade >/dev/null; then
      sleep 5
    else
      return 0
    fi
  done
}

apt_guard_start(){
  wait_for_apt
  CNF_CONF="/etc/apt/apt.conf.d/50command-not-found"
  if [ -f "$CNF_CONF" ]; then mv "$CNF_CONF" "${CNF_CONF}.disabled"; CNF_DISABLED=1; else CNF_DISABLED=0; fi
}

apt_guard_end(){
  if [ "${CNF_DISABLED:-0}" = "1" ] && [ -f "${CNF_CONF}.disabled" ]; then mv "${CNF_CONF}.disabled" "$CNF_CONF"; fi
}

# ===== Packages Installation =====
say "${Y}📦 Packages တင်နေပါတယ်...${Z}"
apt_guard_start
apt-get update -y >/dev/null
apt-get install -y curl ufw jq python3 python3-flask python3-apt iproute2 conntrack ca-certificates openssl >/dev/null
apt_guard_end

# Stop old services
systemctl stop zivpn.service 2>/dev/null || true
systemctl stop zivpn-web.service 2>/dev/null || true

# ===== Paths & Folders =====
BIN="/usr/local/bin/zivpn"
CFG="/etc/zivpn/config.json"
USERS="/etc/zivpn/users.json"
ENVF="/etc/zivpn/web.env"
mkdir -p /etc/zivpn

# ===== Download ZIVPN binary =====
say "${Y}⬇️ ZIVPN binary ကို ဒေါင်းနေပါတယ်...${Z}"
PRIMARY_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
if ! curl -fsSL -o "$BIN" "$PRIMARY_URL"; then
  say "${R}❌ Download failed!${Z}"
  exit 1
fi
chmod +x "$BIN"

# ===== SSL Certs =====
if [ ! -f /etc/zivpn/zivpn.crt ]; then
  say "${Y}🔐 SSL စိတျဖိုင်တွေ ဖန်တီးနေပါတယ်...${Z}"
  openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=MM/ST=Yangon/L=Yangon/O=UPK/OU=Net/CN=zivpn" \
    -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt" >/dev/null 2>&1
fi

# ===== Web Admin Credentials =====
say "${Y}🔒 Web Admin Login UI သတ်မှတ်ချက်များ${Z}"
read -r -p "Web Admin Username (Enter=admin): " WEB_USER
WEB_USER=${WEB_USER:-admin}
read -r -s -p "Web Admin Password: " WEB_PASS; echo
WEB_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

echo "WEB_ADMIN_USER=${WEB_USER}" > "$ENVF"
echo "WEB_ADMIN_PASSWORD=${WEB_PASS}" >> "$ENVF"
echo "WEB_SECRET=${WEB_SECRET}" >> "$ENVF"
chmod 600 "$ENVF"

# ===== Initial Config =====
if [ ! -f "$CFG" ]; then
  echo '{"listen":":5667","auth":{"mode":"passwords","config":["zi"]},"obfs":"zivpn"}' > "$CFG"
fi
[ -f "$USERS" ] || echo "[]" > "$USERS"

# ===== systemd: ZIVPN Server =====
cat >/etc/systemd/system/zivpn.service <<'EOF'
[Unit]
Description=ZIVPN UDP Server
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
[Install]
WantedBy=multi-user.target
EOF

# ===== Web UI (Flask) Python Script =====
cat >/etc/zivpn/web.py <<'PY'
from flask import Flask, jsonify, render_template_string, request, redirect, url_for, session, make_response
import json, re, subprocess, os, tempfile, hmac
from datetime import datetime, timedelta

USERS_FILE = "/etc/zivpn/users.json"
CONFIG_FILE = "/etc/zivpn/config.json"
LOGO_URL = "https://raw.githubusercontent.com/1k2k-vip/kso-udp/refs/heads/main/icon.png"

HTML = """<!doctype html>
<html lang="my"><head><meta charset="utf-8">
<title>ZIVPN User Panel</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 :root{--bg:#ffffff; --fg:#111; --card:#fafafa; --bd:#e5e5e5; --ok:#0a8a0a; --bad:#c0392b;}
 body{font-family:system-ui;margin:24px;background:var(--bg);color:var(--fg)}
 .box{padding:15px;border:1px solid var(--bd);border-radius:12px;background:var(--card);margin-bottom:20px}
 .btn{padding:8px 15px;border-radius:20px;border:1px solid #ccc;cursor:pointer;text-decoration:none;display:inline-block}
 table{width:100%;border-collapse:collapse}
 th,td{padding:10px;border:1px solid var(--bd);text-align:left}
 .pill{padding:4px 10px;border-radius:10px;font-size:0.85em}
 .ok{background:#eaffe6;color:var(--ok)}
 .bad{background:#ffecec;color:var(--bad)}
</style></head>
<body>
<header style="display:flex;align-items:center;gap:15px;margin-bottom:20px">
  <img src="{{logo}}" style="height:50px;border-radius:10px">
  <h1>KSO-VIP Control</h1>
</header>
{% if not session.get('auth') %}
 <form method="post" action="/login" class="box" style="max-width:300px;margin:auto">
  <h3>Login</h3>
  <input name="u" placeholder="Username" style="width:100%;margin-bottom:10px" required><br>
  <input name="p" type="password" placeholder="Password" style="width:100%;margin-bottom:10px" required><br>
  <button class="btn" type="submit">Login</button>
 </form>
{% else %}
 <a href="/logout" class="btn">Logout</a>
 <form method="post" action="/add" class="box">
  <h3>Add User</h3>
  <input name="user" placeholder="User" required>
  <input name="password" placeholder="Pass" required>
  <input name="expires" placeholder="Days (e.g. 30)">
  <button class="btn" type="submit">Save</button>
 </form>
 <table>
  <tr><th>User</th><th>Pass</th><th>Expires</th><th>Status</th><th>Action</th></tr>
  {% for u in users %}
  <tr>
   <td>{{u.user}}</td><td>{{u.password}}</td><td>{{u.expires}}</td>
   <td><span class="pill {{'ok' if u.status=='Online' else 'bad'}}">{{u.status}}</span></td>
   <td><form method="post" action="/delete" style="display:inline"><input type="hidden" name="user" value="{{u.user}}"><button type="submit">Delete</button></form></td>
  </tr>
  {% endfor %}
 </table>
{% endif %}
</body></html>"""

app = Flask(__name__)
app.secret_key = os.environ.get("WEB_SECRET","dev")

def load_users():
    try:
        with open(USERS_FILE,"r") as f: return json.load(f)
    except: return []

def sync_vpn():
    users = load_users()
    pws = [u['password'] for u in users if 'password' in u]
    with open(CONFIG_FILE,"r") as f: cfg = json.load(f)
    cfg['auth']['config'] = pws
    with open(CONFIG_FILE,"w") as f: json.dump(cfg, f, indent=2)
    subprocess.run("systemctl restart zivpn.service", shell=True)

@app.route("/")
def index():
    users = load_users()
    for u in users: u['status'] = "Offline" # Simplification for status
    return render_template_string(HTML, users=users, logo=LOGO_URL)

@app.route("/login", methods=["POST"])
def login():
    if request.form.get("u") == os.environ.get("WEB_ADMIN_USER") and request.form.get("p") == os.environ.get("WEB_ADMIN_PASSWORD"):
        session['auth'] = True
    return redirect("/")

@app.route("/logout")
def logout():
    session.pop('auth', None)
    return redirect("/")

@app.route("/add", methods=["POST"])
def add():
    if not session.get('auth'): return redirect("/")
    users = load_users()
    new_user = {"user": request.form['user'], "password": request.form['password'], "expires": request.form['expires']}
    users.append(new_user)
    with open(USERS_FILE,"w") as f: json.dump(users, f)
    sync_vpn()
    return redirect("/")

@app.route("/delete", methods=["POST"])
def delete():
    if not session.get('auth'): return redirect("/")
    users = [u for u in load_users() if u['user'] != request.form['user']]
    with open(USERS_FILE,"w") as f: json.dump(users, f)
    sync_vpn()
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
PY

# ===== Web Service systemd =====
cat >/etc/systemd/system/zivpn-web.service <<'EOF'
[Unit]
Description=ZIVPN Web Panel
After=network.target
[Service]
Type=simple
User=root
EnvironmentFile=/etc/zivpn/web.env
ExecStart=/usr/bin/python3 /etc/zivpn/web.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# ===== Networking & Firewall =====
say "${Y}🌐 Networking rules ချနေပါတယ်...${Z}"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
IFACE=$(ip -4 route ls | awk '/default/ {print $5; exit}')
iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE

ufw allow 5667/udp >/dev/null 2>&1
ufw allow 6000:19999/udp >/dev/null 2>&1
ufw allow 8080/tcp >/dev/null 2>&1

# ===== Start All =====
systemctl daemon-reload
systemctl enable --now zivpn.service
systemctl enable --now zivpn-web.service

IP=$(curl -s https://ifconfig.me)
echo -e "\n$LINE\n${G}✅ Install ပြီးပါပြီ!${Z}"
echo -e "${C}Web UI :${Z} ${Y}http://$IP:8080${Z}"
echo -e "${C}User   :${Z} ${Y}$WEB_USER${Z}"
echo -e "$LINE"
