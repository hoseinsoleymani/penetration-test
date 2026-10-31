# راهنمای کوتاه فارسی NextAudit

NextAudit یک ابزار CLI پایتونی برای **بازبینی اولیهٔ امنیت سایت‌هایی است که مالک آن‌ها هستید یا مجوز تست دارید**. عملکرد پیش‌فرض فقط GET است و برای محدودکردن فشار روی سرور، سقف تعداد درخواست، سرعت و اندازهٔ پاسخ دارد.

## نصب

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
nextaudit --help
```

## استفاده

```bash
nextaudit scan -u https://app.example.com --authorized -o reports/scan.json
nextaudit scan -u http://127.0.0.1:8000 --allow-local --authorized
nextaudit demo-scan
nextaudit demo  # آزمایش مجزای پرداخت روی لوکال
```

برای بررسی بیشتر گزینه‌ها از `nextaudit scan --help` استفاده کنید. خروجی JSON، Markdown و SARIF قابل تهیه است. شناسایی الگوهای جاوااسکریپت مثل `eval` یا `dangerouslySetInnerHTML` **اثبات باگ نیست**؛ بررسی دستی لازم است. ابزار نمی‌تواند همهٔ آسیب‌پذیری‌های بک‌اند، منطق کسب‌وکار، IDOR یا SQL Injection را به‌طور قطعی پیدا کند.

اسکریپت‌های تست پرداخت و race فقط برای محیط لوکال یا staging و حساب‌های آزمایشی هستند؛ به محیط واقعی مالی وصل نکنید. برای جزئیات و تمام دستورها [README اصلی](../README.md) را بخوانید.
