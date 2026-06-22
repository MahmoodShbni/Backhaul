# مبهم‌سازی و استتار TLS برای ترنسپورت TCP

این نسخه دو قابلیت مستقل به ترنسپورت `tcp` اضافه می‌کند تا امضای پکت‌ها
نسبت به Backhaul اصلی عوض شود و DPI نتواند الگوی ثابت را تشخیص دهد:

1. `obfuscation` — رمزگذاری جریان با AES-256-CTR (حذف امضای ثابت).
2. `tls_camouflage` — پیچیدن کل تونل داخل یک TLS واقعی با **اثرانگشت Chrome
   (uTLS)** و **SNIِ یک دامین واقعی**؛ ترافیک شبیه HTTPS معمولی می‌شود.

**پیشنهاد:** برای مقاومت بیشتر فقط `tls_camouflage` را روشن کنید. این حالت
از `obfuscation` قوی‌تر است، چون ترافیک به‌جای «جریان تصادفیِ مشکوک»، یک
HTTPSِ معمولی با SNI واقعی دیده می‌شود. هر دو را هم می‌توان هم‌زمان روشن کرد.

---

## قبل از بیلد (مهم)
این قابلیت به کتابخانه‌ی uTLS وابسته است. قبل از کامپایل یک‌بار اجرا کنید:

```bash
go mod tidy
go build -o backhaul .
```

`go mod tidy` خودش uTLS و وابستگی‌هایش را دانلود و `go.sum` را کامل می‌کند.

---

## استتار TLS با اثرانگشت Chrome + SNI

در توپولوژی reverse تو: سرور ایران = listener، سرور خارج = dialer.
سمت dialer (کلاینت) ClientHelloِ شبیه‌Chrome را با SNI می‌فرستد؛ سمت listener
(سرور) TLS را با یک گواهی terminate می‌کند.

```toml
[server]                       # سرور ایران
bind_addr = "0.0.0.0:443"
transport = "tcp"
token = "your-shared-token"
ports = ["8080=80"]
tls_camouflage = true
sni = "www.microsoft.com"      # برای CN گواهیِ self-signed استفاده می‌شود
# اختیاری: گواهی واقعی برای بهترین استتار
# tls_cert = "/etc/letsencrypt/live/yourdomain/fullchain.pem"
# tls_key  = "/etc/letsencrypt/live/yourdomain/privkey.pem"

[client]                       # سرور خارج
remote_addr = "SERVER_IP:443"
transport = "tcp"
token = "your-shared-token"
connection_pool = 8
tls_camouflage = true
sni = "www.microsoft.com"      # باید با سرور یکی باشد
tls_fingerprint = "chrome"     # chrome | firefox | safari | edge | ios | android | random
tls_insecure = true            # برای گواهی self-signed؛ با گواهی واقعی false کن
```

نکته‌ها:
- `sni` دو طرف باید یکی باشد. این همان دامینی است که در ClientHello روی سیم
  دیده می‌شود؛ یک دامین پرترافیک و بی‌حاشیه انتخاب کن.
- اگر `tls_cert`/`tls_key` ندهی، سرور موقع استارت یک گواهی self-signed برای
  همان `sni` می‌سازد و کلاینت با `tls_insecure = true` آن را می‌پذیرد.
- بهترین استتار: یک **دامین واقعی** که A-record آن به IP سرور ایران اشاره کند،
  گواهی **Let's Encrypt** بگیر، `tls_cert`/`tls_key` را بده و `tls_insecure`
  را `false` کن. آن‌وقت گواهیِ روی سیم هم با SNI می‌خواند.
- استفاده از پورت `443` استتار را طبیعی‌تر می‌کند.

### اثرانگشت‌ها
مقدار `tls_fingerprint` تعیین می‌کند ClientHello شبیه کدام مرورگر باشد:
`chrome` (پیش‌فرض)، `firefox`، `safari`، `edge`، `ios`، `android`، `random`.

---

## مبهم‌سازی (AES-CTR) — اختیاری
اگر TLS را نمی‌خواهی یا می‌خواهی یک لایه‌ی سبک‌تر داشته باشی:

```toml
[server]
transport = "tcp"
token = "your-shared-token"
obfuscation = true

[client]
transport = "tcp"
token = "your-shared-token"
obfuscation = true
```

این حالت توکن و ساختار ثابت دست‌دهی را رمز می‌کند و با IV و padding تصادفی،
امضای ثابت را حذف می‌کند. اگر `tls_camouflage` روشن باشد، این لایه داخل TLS
قرار می‌گیرد (معمولاً لازم نیست هر دو را روشن کنی).

---

## چطور مطمئن شوم کار می‌کند؟
- **لاگ سرور:** موقع استارت باید ببینی: `TLS camouflage enabled ... sni="..."`.
- **روی سیم:** روی پورت تونل کپچر بگیر و ببین اولین پکت یک ClientHelloِ TLS
  است که SNI داخلش پیداست:
  ```bash
  sudo tcpdump -i any -n -A "tcp port 443" -c 30
  # و کلاینت را ری‌استارت کن تا هندشیک تازه بیفته
  ```
  بایت‌های اول باید `16 03 01 ...` (رکورد هندشیک TLS) باشد و نام دامینِ SNI
  به‌صورت متن دیده شود (SNI طبق استاندارد TLS رمز نیست؛ همین «عادی» بودن مهم است).
- **تست منفی:** `tls_camouflage` را فقط روی یک طرف خاموش کن؛ تونل باید قطع شود.
  اگر بازم وصل شد یعنی کلید اشتباه تایپ شده و هر دو طرف عملاً false هستند.

---

## محدودیت‌ها (صادقانه)
- با گواهی **self-signed**، یک DPI که گواهی را اعتبارسنجی می‌کند می‌تواند بفهمد
  گواهی برای آن دامین معتبر نیست. برای استتار کامل از **دامین + گواهی واقعی**
  استفاده کن (یا پشت nginx/CDN بگذار).
- اثرانگشت Chrome در uTLS نسخه‌ی پین‌شده (v1.6.7) معادل Chrome 120 است. برای
  اثرانگشت‌های جدیدتر، در `go.mod` نسخه‌ی uTLS را بالا ببر (نسخه‌های جدیدتر به
  Go 1.24+ نیاز دارند، آن‌وقت `go` را در `go.mod` هم بالا ببر).
- ServerHelloِ سمت سرور از کتابخانه‌ی استاندارد Go است؛ برای استتار حداکثری
  می‌توانی تونل را پشت یک وب‌سرور/CDN واقعی قرار دهی.
