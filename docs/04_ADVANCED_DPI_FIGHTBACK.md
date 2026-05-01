# تنظیمات پیشرفته و مقابله با فیلترینگ (Fightback)

*(English version follows the Persian version)*

---

## 🇮🇷 تنظیمات پیشرفته و حملات متقابل (فارسی)

پنل شما فقط یک سرویس‌دهنده VPN نیست؛ بلکه یک سلاح تهاجمی علیه سیستم‌های سانسور و فیلترینگ (DPI) است. بخش **Settings** و تب **Fightback / Resilience** برای همین منظور طراحی شده‌اند.

### ۱. تنظیمات دور زدن DPI (DPI Evasion)
در بخش Settings، تنظیماتی وجود دارد که ترافیک سرور شما را "کثیف" می‌کند تا سیستم‌های فیلترینگ نتوانند پکت‌های شما را سرهم‌بندی و آنالیز کنند:
- **TCP Fragment**: پکت‌های TCP را به قطعات بسیار کوچک (مثلا 10 تا 20 بایت) خرد می‌کند. فایروال نمی‌تواند پکت‌ها را سریع سرهم کند و آن‌ها را رها می‌کند.
- **TLS Hello Fragment**: فقط پکت مربوط به شروع اتصال (ClientHello) را خرد می‌کند. این گزینه برای دور زدن فیلترینگ روی دامنه (SNI) بسیار موثر است.
- **IP Fragment**: پکت‌ها را در سطح شبکه (لایه ۳) خرد می‌کند.
- **Mux (Multiplexing)**: چندین اتصال مختلف را از داخل یک تونل واحد عبور می‌دهد تا الگوی تشخیص ترافیک را به هم بریزد.
- **Noise Packets**: پکت‌های زباله و نامربوط در لابلای ترافیک واقعی شما می‌فرستد تا سیستم‌های هوش مصنوعیِ فایروال را گیج کند.

### ۲. تب مقاومت (Resilience)
اگر سرور شما زیر حمله (مثلاً مسدودسازی اکتیو) است، در این تب می‌توانید به سرور دستور دهید با الگوهای نویز و ترافیک فیک، سیستم‌های فایروال را فلج کند:
- **Noise Flood**: ارسال ترافیک سنگینِ بی‌معنی به فایروال محلی.
- **SYN/ACK Spoofing**: ایجاد کانکشن‌های فیک برای پر کردن حافظه فایروال.

### ۳. تب حملات متقابل (Fightback)
**(اخطار: این بخش بسیار قدرتمند است و باید با احتیاط استفاده شود)**
اگر فایروال در حال مسدود کردن آی‌پی شماست، می‌توانید به صورت متقابل به فایروال حمله کنید:
- **RST / FIN Flood**: با ارسال حجم عظیمی از پکت‌های ریست (RST) به فایروال، آن را از کار می‌اندازید.
- **DNS Poisoning**: کش سرورهای DNS فایروال را مسموم می‌کند.
- **Session Hijacking**: تلاش برای در دست گرفتن نشست‌های بازرسی فایروال (DPI Sessions) تا ترافیک شما را نادیده بگیرد.

برای استفاده از این بخش:
1. آی‌پی فایروال یا سرور محدودکننده را وارد کنید.
2. نوع تکنیک را انتخاب کرده و دکمه **Launch** را بزنید.
3. می‌توانید در تب وضعیت، عملیات را متوقف کنید.

---

## 🇬🇧 Advanced DPI Evasion & Fightback (English)

Your panel is not just a VPN server; it is an offensive tool against Deep Packet Inspection (DPI) censorship systems. The **Settings** and **Fightback** tabs are built for this purpose.

### 1. DPI Evasion Settings
Located in the main Settings, these options "dirty" your traffic so firewalls cannot reassemble and analyze your packets:
- **TCP Fragment**: Chops TCP packets into tiny pieces (e.g., 10-20 bytes). Firewalls drop them because reassembling takes too much memory.
- **TLS Hello Fragment**: Only fragments the TLS handshake (ClientHello). Extremely effective for bypassing SNI (domain) blocking.
- **IP Fragment**: Fragments packets at the network layer (Layer 3).
- **Mux (Multiplexing)**: Combines multiple TCP connections into a single tunnel to scramble traffic patterns.
- **Noise Packets**: Injects garbage packets randomly into your stream to confuse AI/ML-based traffic analysis.

### 2. Resilience Tab
If your server is actively being blocked or probed by a firewall, you can trigger defensive operations:
- **Noise Flood**: Overwhelms the local firewall with meaningless traffic.
- **SYN/ACK Spoofing**: Creates fake handshakes to exhaust the firewall's state tables.

### 3. Fightback Tab
**(WARNING: This feature is highly aggressive. Use with caution)**
If a firewall is actively blocking your IP, you can launch counter-attacks against the censorship infrastructure:
- **RST / FIN Flood**: Floods the firewall's inspection engines with reset packets, blinding it.
- **DNS Poisoning**: Poisons the firewall's DNS cache resolvers.
- **Session Hijacking**: Attempts to hijack the firewall's active DPI sessions so it ignores your real traffic.

To use:
1. Enter the Target IP of the firewall/censor.
2. Select the technique and click **Launch**.
3. You can stop the operation at any time from the status section.
