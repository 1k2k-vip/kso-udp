#!/bin/bash
# ZIVPN UDP Server + Web UI (Full Version with Key Gate)
# Features: Key API Gate, Auto 30-Day, Auto Port, Sync Config

set -euo pipefail

# ===== Pretty Colors =====
B="\e[1;34m"; G="\e[1;32m"; Y="\e[1;33m"; R="\e[1;31m"; C="\e[1;36m"; Z="\e[0m"
LINE="${B}────────────────────────────────────────────────────────${Z}"

echo -e "\n$LINE\n${G}🌟 ZIVPN Full Server + Web UI Installer${Z}\n$LINE"

# ===== Root check =====
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${R}Error: root user ဖြင့်သာ run ပါ။${Z}"; exit 1
fi

# =====================================================================
#                   ONE-TIME KEY GATE (API စစ်ဆေးခြင်း)
# =====================================================================
KEY_API_URL="http://103.114.203.183:8088"

consume_key() {
  local _key="$1"
  local _url="${KEY_API_URL}/api/consume"
  
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update && apt-get install -y curl >/dev/null
  fi

  echo -e "${Y}🔑 One-time key ကို စစ်ဆေးနေပါသည်...${Z}"
  local resp
  resp=$(curl -fsS -X POST "$_url" \
           -H 'Content-Type: application/json' \
           -d "{\"key\":\"${_key}\"}" 2>&1) || {
    echo -e "${R}❌ Key server ချိတ်ဆက်မရပါ: $resp${Z}"
    exit 1
  }

  if echo "$resp" | grep -q '"ok":\s*true'; then
    echo -e "${G}✅ Key မှန်ကန်ပါသည် (Consumed) - ဆက်လက်လုပ်ဆောင်ပါမည်${Z}"
    return 0
  else
    echo -e "${R}❌ Key မမှန်ပါ သို့မဟုတ် အသုံးပြုပြီးသားဖြစ်နေသည်: $resp${Z}"
    return 1
  fi
}

# Key Prompt
while :; do
  echo -ne "${C}Enter One-Time Key: ${Z}"
  read -r -s ONE_TIME_KEY
  echo
  if [ -z "${ONE_TIME_KEY}" ]; then continue; fi
  if consume_key "$ONE_TIME_KEY"; then break; else
    echo -e "${Y}🔁 Key ပြန်ထည့်ပေးပါ...${Z}"
  fi
done

# ===== Install Packages =====
echo -e "${Y}📦 Dependencies များ တင်နေသည်...${Z}"
apt-get update -y >/dev/null
apt-get install -y curl ufw jq python3 python3-flask iproute2 conntrack ca-certificates openssl >/dev/null

# ===== Folders & Paths =====
mkdir -p /etc/zivpn
BIN="/usr/local/bin/zivpn"
CFG="/etc/zivpn/config.json"
USERS="/etc/zivpn/users.json"
ENVF="/etc/zivpn/web.env"

# ===== Download Binary =====
echo -e "${Y}⬇️ ZIVPN binary ဒေါင်းလုဒ်ဆွဲနေသည်...${Z}"
curl -fsSL -o "$BIN" "https://github.com/zahidbd2/udp-zivpn/releases/latest/download/udp-zivpn-linux-amd64"
chmod +x "$BIN"

# ===== SSL Certs =====
if [ ! -f /etc/zivpn/zivpn.crt ]; then
  openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=MM/ST=Yangon/O=UPK/CN=zivpn" \
    -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt" >/dev/null 2>&1
fi

# ===== Web Login Credentials =====
echo -e "${G}🔒 Web Admin Login သတ်မှတ်ပါ${Z}"
read -r -p "Username: " WEB_USER
read -r -s -p "Password: " WEB_PASS; echo
WEB_SECRET=$(openssl rand -hex 16)

{
  echo "WEB_ADMIN_USER=${WEB_USER}"
  echo "WEB_ADMIN_PASSWORD=${WEB_PASS}"
  echo "WEB_SECRET=${WEB_SECRET}"
} > "$ENVF"

# Initial config
echo '{"auth":{"mode":"passwords","config":["zi"]},"listen":":5667","cert":"/etc/zivpn/zivpn.crt","key":"/etc/zivpn/zivpn.key","obfs":"zivpn"}' > "$CFG"
[ -f "$USERS" ] || echo "[]" > "$USERS"

# ===== Web.py (FULL VERSION) =====
cat > /etc/zivpn/web.py << 'PY'
import os, json, re, subprocess, hmac
from flask import Flask, jsonify, render_template_string, request, redirect, url_for, session
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("WEB_SECRET", "dev")

USERS_FILE = "/etc/zivpn/users.json"
CONFIG_FILE = "/etc/zivpn/config.json"
LOGO_URL = "https://raw.githubusercontent.com/Upk123/upkvip-ziscript/refs/heads/main/20251018_231111.png"

def get_data(p, d):
    try:
        with open(p, "r") as f: return json.load(f)
    except: return d

def save_data(p, d):
    with open(p, "w") as f: json.dump(d, f, indent=2)

def pick_port():
    users = get_data(USERS_FILE, [])
    used = {str(u.get("port")) for u in users if u.get("port")}
    for p in range(6000, 20000):
        if str(p) not in used: return str(p)
    return "7000"

HTML = """
<!doctype html>
<html lang="my">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>KSO-VIP User Manager</title>
    <style>
        body { font-family: sans-serif; background: #f0f2f5; margin: 0; padding: 20px; }
        .box { max-width: 900px; margin: auto; background: #fff; padding: 20px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        header { display: flex; align-items: center; gap: 15px; border-bottom: 2px solid #eee; padding-bottom: 15px; margin-bottom: 20px; }
        .logo { width: 60px; height: 60px; border-radius: 12px; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 8px; box-sizing: border-box; }
        .btn { background: #1877f2; color: #fff; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-weight: bold; text-decoration: none; display: inline-block; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #eee; padding: 12px; text-align: left; }
        th { background: #f8f9fa; }
        .badge { padding: 4px 8px; border-radius: 5px; font-size: 12px; background: #e7f3ff; color: #1877f2; }
    </style>
</head>
<body>
    <div class="box">
        {% if not session.get('auth') %}
            <div style="text-align:center; padding: 40px 0;">
                <img src="{{logo}}" class="logo">
                <h2>Admin Login</h2>
                <form method="post" action="/login">
                    <input name="u" placeholder="Username" required>
                    <input name="p" type="password" placeholder="Password" required>
                    <button class="btn" style="width:100%">Login</button>
                </form>
            </div>
        {% else %}
            <header>
                <img src="{{logo}}" class="logo">
                <div><h1 style="margin:0">KSO-VIP</h1><p style="margin:0;color:#666">UDP User Panel</p></div>
                <div style="margin-left:auto"><a href="/logout" class="btn" style="background:#666">Logout</a></div>
            </header>

            <h3>➕ အသုံးပြုသူ အသစ်ထည့်ရန်</h3>
            <form method="post" action="/add" style="background:#f9f9f9; padding:20px; border-radius:10px;">
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:15px;">
                    <input name="user" placeholder="Username" required>
                    <input name="pass" placeholder="Password" required>
                    <input name="exp" placeholder="ရက်ပေါင်း (မထည့်ပါက ၃၀ ရက်)">
                    <input name="port" placeholder="Port (မထည့်ပါက အော်တို)">
                </div>
                <button class="btn" style="width:100%; margin-top:10px;">သိမ်းဆည်းမည် (Save User)</button>
            </form>

            <table>
                <tr>
                    <th>Username</th><th>Password</th><th>Expires</th><th>Port</th><th>Action</th>
                </tr>
                {% for u in users %}
                <tr>
                    <td><b>{{ u.user }}</b></td>
                    <td>{{ u.password }}</td>
                    <td><span class="badge">{{ u.expires }}</span></td>
                    <td>{{ u.port }}</td>
                    <td>
                        <form method="post" action="/delete" style="display:inline;">
                            <input type="hidden" name="user" value="{{ u.user }}">
                            <button class="btn" style="background:#e41e3f; padding: 5px 10px;" onclick="return confirm('ဖျက်မှာ သေချာပါသလား?')">ဖျက်မည်</button>
                        </form>
                    </td>
                </tr>
                {% endfor %}
            </table>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    users = get_data(USERS_FILE, [])
    return render_template_string(HTML, logo=LOGO_URL, users=users)

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("u"); p = request.form.get("p")
    if hmac.compare_digest(u, os.environ.get("WEB_ADMIN_USER", "")) and hmac.compare_digest(p, os.environ.get("WEB_ADMIN_PASSWORD", "")):
        session['auth'] = True
    return redirect(url_for('index'))

@app.route("/logout")
def logout():
    session.pop('auth', None); return redirect(url_for('index'))

@app.route("/add", methods=["POST"])
def add():
    if not session.get('auth'): return redirect('/')
    user = request.form.get("user").strip()
    pw = request.form.get("pass").strip()
    exp_in = request.form.get("exp").strip()
    port = request.form.get("port").strip()

    # --- Auto 30 Days ---
    if not exp_in:
        exp = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
    elif exp_in.isdigit():
        exp = (datetime.now() + timedelta(days=int(exp_in))).strftime("%Y-%m-%d")
    else: exp = exp_in

    # --- Auto Port ---
    if not port: port = pick_port()

    users = get_data(USERS_FILE, [])
    users = [u for u in users if u['user'] != user]
    users.append({"user": user, "password": pw, "expires": exp, "port": port})
    save_data(USERS_FILE, users)

    # Sync Config
    cfg = get_data(CONFIG_FILE, {})
    cfg['auth']['config'] = [u['password'] for u in users]
    save_data(CONFIG_FILE, cfg)
    
    subprocess.run(["systemctl", "restart", "zivpn"])
    return redirect('/')

@app.route("/delete", methods=["POST"])
def delete():
    if not session.get('auth'): return redirect('/')
    user = request.form.get("user")
    users = [u for u in get_data(USERS_FILE, []) if u['user'] != user]
    save_data(USERS_FILE, users)
    
    cfg = get_data(CONFIG_FILE, {})
    cfg['auth']['config'] = [u['password'] for u in users]
    save_data(CONFIG_FILE, cfg)
    
    subprocess.run(["systemctl", "restart", "zivpn"])
    return redirect('/')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
PY

# ===== Systemd Setup =====
cat > /etc/systemd/system/zivpn.service <<EOF
[Unit]
Description=ZIVPN UDP Server
After=network.target

[Service]
ExecStart=$BIN server -c $CFG
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/zivpn-web.service <<EOF
[Unit]
Description=ZIVPN Web Manager
After=network.target

[Service]
EnvironmentFile=$ENVF
ExecStart=/usr/bin/python3 /etc/zivpn/web.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# ===== Network Rules =====
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A POSTROUTING -j MASQUERADE
ufw allow 5667/udp
ufw allow 6000:19999/udp
ufw allow 8080/tcp

# ===== Start Services =====
systemctl daemon-reload
systemctl enable --now zivpn zivpn-web

IP=$(hostname -I | awk '{print $1}')
echo -e "$LINE"
echo -e "${G}✅ အားလုံး အောင်မြင်စွာ တင်ပြီးပါပြီ!${Z}"
echo -e "${C}🌐 Web Admin: http://$IP:8080${Z}"
echo -e "${Y}💡 User အသစ်ထည့်တိုင်း အော်တို ၁ လ နှင့် Port သတ်မှတ်ပေးပါမည်။${Z}"
echo -e "$LINE"
