# مدیریت کاربران | User Management

*(English version follows the Persian version)*

---

## 🇮🇷 مدیریت کاربران (فارسی)

بخش مدیریت کاربران در پنل امکانات بسیار گسترده‌ای برای کنترل کامل روی نحوه استفاده کلاینت‌ها به شما می‌دهد.

### ۱. ویژگی‌های جدول کاربران
در صفحه اصلی، تمام کاربران شما به صورت یک جدول نمایش داده می‌شوند. ویژگی‌های هر سطر:
- **Status (وضعیت)**: نشان می‌دهد آیا کاربر فعال (Active) است، غیرفعال (Disabled) شده است، یا محدودیت ترافیک/زمان او به پایان رسیده است (Expired).
- **Traffic (ترافیک)**: میزان مصرف شده / کل ترافیک مجاز (بر حسب گیگابایت).
- **Expiry (انقضا)**: تاریخ پایان اعتبار اکانت.
- **Actions (عملیات)**: دکمه‌هایی برای دریافت لینک اتصال (کانفیگ)، ویرایش مشخصات، تمدید و حذف کاربر.

### ۲. ویرایش و تمدید کاربر
با کلیک روی دکمه **ویرایش (آیکون مداد)** جلوی هر کاربر:
- **تغییر ترافیک**: می‌توانید سقف ترافیک کاربر را کم یا زیاد کنید. اگر می‌خواهید اکانت نامحدود باشد، مقدار 0 را وارد کنید.
- **تغییر زمان**: می‌توانید تاریخ انقضا را تمدید کنید.
- **افزودن ترافیک بدون ریست (Add Traffic)**: به جای تغییر سقف کلی، می‌توانید به مصرف فعلی کاربر یک مقدار مشخص گیگابایت اضافه کنید (مثلاً ۵ گیگابایت حجم اضافه).
- **یادداشت‌ها (Note)**: می‌توانید یادداشتی برای کاربر بنویسید (مثلاً "پرداخت نشده" یا "دوست علی"). این یادداشت فقط برای شما نمایش داده می‌شود.

### ۳. عملیات گروهی (Bulk Actions)
در بالای جدول، دکمه **Bulk Actions** قرار دارد. با تیک زدن چند کاربر می‌توانید:
- **Enable/Disable**: به صورت گروهی اکانت‌ها را فعال یا قطع کنید.
- **Reset Traffic**: ترافیک مصرفی همه آن‌ها را صفر کنید.
- **Delete**: همه را با هم حذف کنید.

### ۴. مانیتورینگ ترافیک (Traffic Analytics)
در صفحه اصلی، نمودارهایی برای مانیتورینگ لحظه‌ای مصرف ترافیک و مقایسه مصرف کاربران پرمصرف (Top Consumers) وجود دارد. سیستم به صورت خودکار هر ۳۰ ثانیه مصرف کاربران را با دیتابیس همگام‌سازی می‌کند.

---

## 🇬🇧 User Management (English)

The user management module provides extensive controls over client usage.

### 1. User Table Features
On the main page, all your users are displayed in a table:
- **Status**: Shows if the user is Active, Disabled, or Expired (due to data or time limits).
- **Traffic**: Data used / Total allowed (in GB).
- **Expiry**: Account expiration date.
- **Actions**: Buttons to get config links, edit details, renew, or delete the user.

### 2. Editing & Renewing Users
Clicking the **Edit (pencil icon)** next to a user allows you to:
- **Change Traffic Limit**: Adjust the total allowed data. Set to 0 for unlimited.
- **Change Expiry Date**: Renew the account by extending the date.
- **Add Traffic (No Reset)**: Add specific GBs directly to their limit without resetting their current usage.
- **Notes**: Add internal memos (e.g., "Unpaid" or "VIP"). This is only visible to the admin.

### 3. Bulk Actions
By checking multiple users and clicking the **Bulk Actions** dropdown at the top:
- **Enable/Disable**: Mass activate or suspend accounts.
- **Reset Traffic**: Reset data consumption to 0 GB for all selected users.
- **Delete**: Mass delete users.

### 4. Traffic Analytics
The main dashboard includes live charts for monitoring traffic consumption over time and identifying Top Consumers. The backend automatically syncs network usage to the database every 30 seconds to ensure strict limit enforcement.
