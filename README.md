config.json:

{
  "tg_token": "ВАШ_ТОКЕН",
  "my_telegram_id": 123456789,
  "email_login": "DOMAIN\\user",
  "email_user": "user@company.com",
  "email_pass": "ПАРОЛЬ",
  "imap_server": "imap.company.com:993",
  "smtp_host": "smtp.company.com",
  "smtp_port": "587",
  "auth_type": "plain",
  "poll_interval_sec": 30,
  "retry_delay_sec": 20
}

Для Plain (Gmail/Yandex/587 порт) используйте auth_type: "plain". Для Exchange — "ntlm"
