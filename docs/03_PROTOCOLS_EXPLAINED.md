# راهنمای جامع پروتکل‌ها | Comprehensive Protocols Guide

*(English version follows the Persian version)*

---

## 🇮🇷 راهنمای جامع پروتکل‌ها (فارسی)

پنل شما به صورت بومی از ۱۷ پروتکل مختلف پشتیبانی می‌کند که می‌توانید هرکدام را بر اساس نیاز خود در منوی Settings فعال یا غیرفعال کنید.

### 🟢 پروتکل‌های اصلی Xray (پایداری و امنیت بالا)
این پروتکل‌ها توسط هسته قدرتمند Xray پردازش می‌شوند و بهترین انتخاب برای دور زدن فیلترینگ شدید (مثل GFW یا فیلترینگ ایران) هستند.

1. **VLESS + XHTTP + Reality**: جدیدترین و مقاوم‌ترین پروتکل. از متد انتقال XHTTP استفاده می‌کند که ترافیک شما را دقیقاً شبیه ترافیک طبیعی وب‌گردی می‌کند. به شدت توصیه می‌شود.
2. **VLESS + Vision + Reality**: استاندارد طلایی و محبوب‌ترین روش. پایین‌ترین پینگ و بالاترین سرعت را دارد اما نیازمند آی‌پی سرور "تمیز" (فیلتر نشده) است.
3. **VLESS + Reverse Tunnel**: برای شرایطی که سرور شما در ایران است و می‌خواهید ترافیک را به یک سرور خارج (بدون نیاز به پورت‌فورواردینگ) متصل کنید.
4. **Trojan + CDN / WS**: وقتی آی‌پی سرور شما فیلتر شده است، این پروتکل ترافیک شما را از طریق دامنه‌های کلودفلر (Cloudflare) هدایت می‌کند.

### 🔵 پروتکل‌های مستقل (Standalone)
این پروتکل‌ها برنامه‌های اختصاصی خود را دارند و برای شرایط خاص شبکه طراحی شده‌اند. (توجه: نرم‌افزار سرور آن‌ها باید روی سرور شما نصب باشد تا کار کنند).

5. **Hysteria 2**: از پروتکل UDP استفاده می‌کند. **ناجی اینترنت‌های بی‌کیفیت!** اگر اینترنت شما پینگ بالا و افت بسته (Packet loss) دارد، سرعت این پروتکل شما را شگفت‌زده خواهد کرد.
6. **TUIC v5**: مشابه Hysteria بر بستر QUIC کار می‌کند اما با تمرکز بر کاهش تاخیر (0-RTT) برای باز شدن سریع‌تر وب‌سایت‌ها.
7. **ShadowTLS**: اتصالات را دقیقا شبیه ترافیک نرم‌افزارهای سازمانی یا بانکی می‌کند تا فایروال‌ها فریب بخورند.
8. **Mieru**: تغییر دهنده پویا و مداوم ساختار پکت‌ها؛ مناسب برای مقابله با فایروال‌های مبتنی بر هوش مصنوعی.
9. **NaiveProxy**: ترافیک شما را داخل موتور مرورگر Chromium مخفی می‌کند. مقاوم‌ترین پروتکل در برابر فیلترینگ چین.
10. **AmneziaWG**: نسخه ضد فیلترِ WireGuard. هدرهای ترافیک را تغییر می‌دهد تا فایروال نتواند الگوی وایرگارد را تشخیص دهد.
11. **WireGuard / OpenVPN**: پروتکل‌های کلاسیک و پایدار برای شرایطی که فیلترینگ سخت‌گیرانه‌ای وجود ندارد.

---

## 🇬🇧 Comprehensive Protocols Guide (English)

Your panel natively supports 17 different protocols. You can enable or disable them in the Settings menu based on your network environment.

### 🟢 Core Xray Protocols (High Stability & Security)
Processed by the powerful Xray-core, these are the best choices for bypassing severe censorship (e.g., GFW or Iran's firewall).

1. **VLESS + XHTTP + Reality**: The newest and most resilient protocol. Uses the XHTTP transport to make your traffic indistinguishable from normal web browsing. Highly recommended.
2. **VLESS + Vision + Reality**: The golden standard. Offers the lowest ping and highest speeds, but requires a "clean" (unblocked) server IP.
3. **VLESS + Reverse Tunnel**: Used when your server is behind a NAT/restricted network and you want to tunnel traffic to a foreign server without port-forwarding.
4. **Trojan + CDN / WS**: When your server IP is blocked, this routes your traffic through Cloudflare (or other CDNs) to hide the destination IP.

### 🔵 Standalone Protocols
These protocols use their own specialized binaries and are designed for specific network conditions. *(Note: Their respective server software must be installed on your Linux machine).*

5. **Hysteria 2**: UDP-based protocol. **The savior of poor internet connections!** If your network has high packet loss and jitter, this will shock you with its speed.
6. **TUIC v5**: Similar to Hysteria, based on QUIC, but heavily optimized for latency reduction (0-RTT handshake) for snappy web browsing.
7. **ShadowTLS**: Deeply modifies TLS handshakes to mimic enterprise/banking traffic, easily bypassing strict DPI (Deep Packet Inspection) rules.
8. **Mieru**: Dynamically mutates packet structures to evade AI/ML-based firewalls.
9. **NaiveProxy**: Hides your traffic inside a literal Chromium browser network stack. The most unblockable protocol against advanced censorship.
10. **AmneziaWG**: Anti-censorship fork of WireGuard. Modifies packet headers so firewalls cannot detect the WireGuard signature.
11. **WireGuard / OpenVPN**: Classic, reliable tunneling protocols for networks without strict censorship.
