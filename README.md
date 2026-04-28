<p align="center">
  <img src="static/logo.png" alt="Spiritus Logo" width="200">
</p>

<h1 align="center">Spiritus — VPN Management Panel</h1>

<p align="center">
  <strong>Modern, feature-rich VPN management panel for Xray/V2Ray</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Flask-3.0-green.svg" alt="Flask 3.0">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
</p>

[🇬🇧 English](#english) | [🇮🇷 فارسی](#فارسی)

---

<a id="english"></a>

## ✨ Features

### User Management
- 🔍 **Search** — Find users by name, UUID, or notes
- 📦 **Bulk Operations** — Update multiple users at once
- 📊 **User Statistics** — Detailed per-user stats and activity history
- 👥 **Groups** — Organize users into groups
- 🤖 **Agent System** — Multi-agent support with quotas

### Reporting & Analytics
- 📈 **Statistics Report** — Overview of all users and traffic
- 📉 **Traffic Analytics** — Daily traffic usage trends
- 🏆 **Top Users** — Identify high-traffic users
- ⚠️ **Expiring Soon** — Users expiring within 7 days

### Backup & Export
- 💾 **Backup/Restore** — Create and restore database backups
- 📄 **CSV Export** — Export user data to CSV
- 📋 **JSON Export** — Export user data to JSON

### System Monitoring
- 💻 **CPU** — Real-time CPU monitoring
- 🧠 **Memory** — RAM usage tracking
- 💾 **Disk** — Storage space monitoring
- 🌐 **Network** — Active connection count

### Multi-Protocol Support
- **VMess** (WebSocket + TLS)
- **VLESS** (Reality & WebSocket)
- **Trojan**
- **gRPC**
- **HTTPUpgrade**
- **ShadowSocks 2022**
- **VLESS + WS + TLS** (CDN compatible)

### DPI Evasion
- TCP segment overlapping & out-of-order delivery
- TTL manipulation
- IP/TCP/TLS fragmentation
- DNS & ICMP tunneling
- Domain fronting

### Security
- 🔒 Enhanced authentication with lockout
- 🛡️ CSRF & XSS protection headers
- 🚫 Rate limiting against brute force
- 📝 Audit logging

### UI/UX
- 🎨 Modern dark theme with glassmorphism
- ⚡ Fast, responsive design
- 📱 Mobile-friendly
- 🔔 Toast notifications

---

## 📦 Installation

### One-Command Install (Recommended)

```bash
bash <(curl -sL https://raw.githubusercontent.com/v74all/Spiritus/main/install.sh)
```

This will automatically:
- Install all dependencies (Python, Xray, etc.)
- Set up a Python virtual environment
- Configure systemd service
- Set up daily auto-update cron job

### Manual Install

```bash
# Clone the repository
git clone https://github.com/v74all/Spiritus.git
cd Spiritus

# Install dependencies
pip3 install -r requirements.txt

# (Optional) Install DPI evasion dependencies
pip3 install -r requirements-dpi.txt

# (Optional) Install network resilience dependencies
pip3 install -r requirements-firewall.txt
```

### Configuration

Set environment variables or edit defaults in `vpn-web.py`:

```bash
export VPN_SERVER_IP="your-server-ip"
export VPN_SERVER_PORT="443"
export VPN_SNI_HOST="www.google.com"
export VPN_WEB_PORT="38471"
export VPN_API_PORT="10085"
```

### Run

```bash
# Direct
python3 vpn-web.py

# As systemd service
sudo cp vpn-panel.service /etc/systemd/system/
sudo systemctl enable vpn-panel
sudo systemctl start vpn-panel
```

### Access

```
URL: http://your-server-ip:38471
Default Password: See vpn-panel-password file after first run
```

### Auto-Update

The installer sets up a daily cron job at 4:00 AM to automatically pull updates from GitHub:

```bash
# Check auto-update status
crontab -l | grep spiritus

# Manual update
cd /opt/spiritus && git pull && sudo systemctl restart vpn-panel
```

---

## 📁 Project Structure

```
Spiritus/
├── vpn-web.py              # Main Flask application
├── scripts/
│   ├── dpi_evasion.py      # DPI evasion techniques
│   ├── firewall_exhaustion.py  # Network resilience testing
│   ├── speed_manager.py    # Traffic control (stub)
│   └── demo_resilience.py          # Demo script
├── static/
│   ├── css/panel.css       # Dark theme styles
│   ├── js/
│   │   ├── panel.js        # Frontend logic
│   │   └── qrcode.js       # QR code generation
│   └── logo.png            # Brand logo
├── templates/
│   ├── panel.html          # Main admin panel
│   ├── sub.html            # User subscription page
│   ├── agent-panel.html    # Agent management panel
│   └── includes/           # Template partials
├── requirements.txt        # Core dependencies
├── requirements-dpi.txt    # DPI evasion dependencies
├── requirements-firewall.txt  # Network resilience dependencies
├── install.sh              # Automated installation script
├── vpn-panel.service       # systemd service file
└── .gitignore
```

---

## 🔧 API

See [API.md](API.md) for full API documentation.

### Quick Reference

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| Users | `/api/users` | GET | List all users |
| Users | `/api/users` | POST | Create new user |
| Users | `/api/users/<name>` | DELETE | Delete user |
| Users | `/api/users/<name>/toggle` | POST | Toggle user status |
| Search | `/api/search?q=<query>` | GET | Search users |
| Analytics | `/api/analytics?days=<n>` | GET | Traffic analytics |
| Backup | `/api/backup/create` | POST | Create backup |
| Export | `/api/export/<format>` | GET | Export data |
| Health | `/api/health` | GET | System health |

---

## ⚠️ Disclaimer

**This project is for educational and authorized testing purposes only.**

- Use these techniques **ONLY** on systems you own or have explicit permission to test
- Unauthorized use of network testing features is **ILLEGAL**
- Always comply with local laws and regulations
- The DPI evasion and network resilience features are designed for protecting privacy in restrictive network environments

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🎉 Credits

- **Xray Project**: https://github.com/XTLS/Xray-core
- **V2Ray Project**: https://www.v2fly.org/
- **Flask**: https://flask.palletsprojects.com/

---

**Version**: 1.0.0 · **Last Updated**: April 2026 · **Status**: Production Ready ✅

---

---

<a id="فارسی"></a>

## 🇮🇷 راهنمای کامل فارسی

### معرفی

**Spiritus** یک پنل مدیریت VPN مدرن و کامل برای Xray/V2Ray است. با این پنل می‌تونید کاربران رو مدیریت کنید، ترافیک رو نظارت کنید، تنظیمات دور زدن DPI رو اعمال کنید و خیلی کارهای دیگه.

---

### ✨ امکانات

#### مدیریت کاربران
- 🔍 **جستجو** — پیدا کردن کاربران بر اساس نام، UUID یا یادداشت
- 📦 **عملیات گروهی** — آپدیت همزمان چند کاربر
- 📊 **آمار کاربر** — آمار تفصیلی و تاریخچه فعالیت هر کاربر
- 👥 **گروه‌ها** — دسته‌بندی کاربران در گروه‌های مختلف
- 🤖 **سیستم عامل** — پشتیبانی از چند عامل با سهمیه مشخص

#### گزارش و تحلیل
- 📈 **گزارش آماری** — نمای کلی کاربران و ترافیک
- 📉 **تحلیل ترافیک** — روند مصرف ترافیک روزانه
- 🏆 **کاربران برتر** — شناسایی کاربران پرترافیک
- ⚠️ **در حال انقضا** — کاربرانی که ظرف ۷ روز منقضی می‌شن

#### پشتیبان‌گیری و خروجی
- 💾 **پشتیبان‌گیری/بازیابی** — ساخت و بازیابی نسخه پشتیبان دیتابیس
- 📄 **خروجی CSV** — خروجی اطلاعات کاربران به فرمت CSV
- 📋 **خروجی JSON** — خروجی اطلاعات کاربران به فرمت JSON

#### نظارت بر سیستم
- 💻 **CPU** — نظارت لحظه‌ای پردازنده
- 🧠 **حافظه** — ردیابی مصرف RAM
- 💾 **دیسک** — نظارت فضای ذخیره‌سازی
- 🌐 **شبکه** — تعداد اتصال‌های فعال

#### پروتکل‌های پشتیبانی‌شده
- **VMess** (WebSocket + TLS)
- **VLESS** (Reality و WebSocket)
- **Trojan**
- **gRPC**
- **HTTPUpgrade**
- **ShadowSocks 2022**
- **VLESS + WS + TLS** (سازگار با CDN)

#### دور زدن DPI
- هم‌پوشانی و تحویل خارج از ترتیب بخش‌های TCP
- دستکاری TTL
- قطعه‌قطعه‌سازی IP/TCP/TLS
- تونل‌زنی DNS و ICMP
- Domain Fronting

#### امنیت
- 🔒 احراز هویت پیشرفته با قفل‌کردن حساب
- 🛡️ محافظت CSRF و XSS
- 🚫 محدودیت نرخ در برابر حملات brute force
- 📝 لاگ‌گذاری حسابرسی

#### رابط کاربری
- 🎨 تم تاریک مدرن با افکت glassmorphism
- ⚡ طراحی سریع و واکنش‌گرا
- 📱 سازگار با موبایل
- 🔔 اعلان‌های Toast

---

### 📦 نصب

#### نصب با یک دستور (پیشنهادی)

```bash
bash <(curl -sL https://raw.githubusercontent.com/v74all/Spiritus/main/install.sh)
```

این دستور به‌صورت خودکار:
- تمام وابستگی‌ها (Python, Xray و غیره) رو نصب می‌کنه
- محیط مجازی Python راه‌اندازی می‌کنه
- سرویس systemd رو تنظیم می‌کنه
- کرون‌جاب آپدیت خودکار روزانه ساعت ۴ صبح تنظیم می‌کنه

#### نصب دستی

```bash
# کلون کردن مخزن
git clone https://github.com/v74all/Spiritus.git
cd Spiritus

# نصب وابستگی‌ها
pip3 install -r requirements.txt

# (اختیاری) نصب وابستگی‌های دور زدن DPI
pip3 install -r requirements-dpi.txt

# (اختیاری) نصب وابستگی‌های تاب‌آوری شبکه
pip3 install -r requirements-firewall.txt
```

---

### ⚙️ تنظیمات

متغیرهای محیطی رو تنظیم کنید یا مقادیر پیش‌فرض رو در `vpn-web.py` تغییر بدید:

```bash
export VPN_SERVER_IP="آی‌پی-سرور-شما"
export VPN_SERVER_PORT="443"
export VPN_SNI_HOST="www.google.com"
export VPN_WEB_PORT="38471"
export VPN_API_PORT="10085"
```

---

### 🚀 اجرا

```bash
# اجرای مستقیم
python3 vpn-web.py

# به‌عنوان سرویس systemd
sudo cp vpn-panel.service /etc/systemd/system/
sudo systemctl enable vpn-panel
sudo systemctl start vpn-panel
```

### دسترسی

```
آدرس: http://آی‌پی-سرور:38471
رمز عبور پیش‌فرض: بعد از اولین اجرا فایل vpn-panel-password رو ببینید
```

---

### 🔄 آپدیت خودکار

نصب‌کننده یک کرون‌جاب روزانه ساعت ۴ صبح تنظیم می‌کنه که آپدیت‌ها رو از GitHub دریافت می‌کنه:

```bash
# بررسی وضعیت آپدیت خودکار
crontab -l | grep spiritus

# آپدیت دستی
cd /opt/spiritus && git pull && sudo systemctl restart vpn-panel
```

---

### 🔧 API

مستندات کامل API رو در [API.md](API.md) ببینید.

#### مرجع سریع

| دسته | آدرس | متد | توضیح |
|------|-------|-----|-------|
| کاربران | `/api/users` | GET | لیست همه کاربران |
| کاربران | `/api/users` | POST | ساخت کاربر جدید |
| کاربران | `/api/users/<name>` | DELETE | حذف کاربر |
| کاربران | `/api/users/<name>/toggle` | POST | فعال/غیرفعال کردن کاربر |
| جستجو | `/api/search?q=<query>` | GET | جستجوی کاربران |
| تحلیل | `/api/analytics?days=<n>` | GET | تحلیل ترافیک |
| پشتیبان | `/api/backup/create` | POST | ساخت پشتیبان |
| خروجی | `/api/export/<format>` | GET | خروجی اطلاعات |
| سلامت | `/api/health` | GET | وضعیت سیستم |

---

### 🔒 نکات امنیتی

1. **رمز عبور پیش‌فرض رو تغییر بدید**
```bash
# از طریق API
curl -X POST http://localhost:38471/api/change-password \
  -H "Content-Type: application/json" \
  -d '{"current_pw":"قدیمی","new_pw":"رمز-قوی-جدید"}'
```

2. **HTTPS رو فعال کنید** (پیشنهادی برای محیط تولید)
```bash
# از nginx reverse proxy با SSL استفاده کنید
```

3. **پشتیبان‌گیری منظم**
```bash
# زمان‌بندی پشتیبان‌گیری روزانه
0 2 * * * /usr/bin/python3 /path/to/backup_script.py
```

4. **نظارت بر سلامت سیستم**
```bash
# بررسی منابع سیستم
curl http://localhost:38471/api/health
```

---

### 🐛 رفع مشکلات

#### پنل اجرا نمیشه
```bash
# بررسی اشغال بودن پورت
netstat -tlnp | grep 38471

# بررسی لاگ‌ها
tail -f /root/vpn-panel.log
```

#### مشکلات دیتابیس
```bash
# پشتیبان‌گیری از دیتابیس فعلی
cp /root/vpn_users.db /root/vpn_users.db.backup

# بازیابی از پشتیبان
python3 -c "import sqlite3; conn = sqlite3.connect('/root/vpn_users.db'); conn.execute('VACUUM'); conn.commit()"
```

#### مشکلات اتصال Xray
```bash
# بررسی وضعیت Xray
systemctl status xray

# ری‌استارت Xray
systemctl restart xray

# بررسی لاگ‌های Xray
journalctl -u xray -f
```

---

### 📈 نکات عملکرد

1. **فعال‌سازی ایندکس دیتابیس**
```sql
CREATE INDEX idx_users_name ON users(name);
CREATE INDEX idx_users_active ON users(active);
CREATE INDEX idx_users_expire ON users(expire_at);
```

2. **بهینه‌سازی نگهداری پشتیبان**
```json
{
  "backup_retention_days": 7
}
```

3. **نگهداری منظم دیتابیس**
```bash
# Vacuum هفتگی
sqlite3 /root/vpn_users.db "VACUUM;"
```

---

### ⚠️ هشدار

**این پروژه فقط برای مقاصد آموزشی و تست مجاز است.**

- از این تکنیک‌ها **فقط** روی سیستم‌هایی استفاده کنید که مالک آن‌ها هستید یا اجازه صریح دارید
- استفاده غیرمجاز از قابلیت‌های تست شبکه **غیرقانونی** است
- همیشه با قوانین محلی خود مطابقت داشته باشید
- قابلیت‌های دور زدن DPI و تاب‌آوری شبکه برای حفظ حریم خصوصی در محیط‌های شبکه محدودکننده طراحی شده‌اند

---

### 📄 مجوز

این پروژه تحت مجوز MIT منتشر شده — فایل [LICENSE](LICENSE) رو ببینید.

---

### 🤝 مشارکت

1. مخزن رو Fork کنید
2. شاخه ویژگی بسازید (`git checkout -b feature/amazing-feature`)
3. تغییرات رو Commit کنید (`git commit -m 'Add amazing feature'`)
4. Push کنید (`git push origin feature/amazing-feature`)
5. یک Pull Request باز کنید

---

### 🎉 تشکر از

- **پروژه Xray**: https://github.com/XTLS/Xray-core
- **پروژه V2Ray**: https://www.v2fly.org/
- **Flask**: https://flask.palletsprojects.com/

---

**نسخه**: 1.0.0 · **آخرین بروزرسانی**: آوریل ۲۰۲۶ · **وضعیت**: آماده تولید ✅