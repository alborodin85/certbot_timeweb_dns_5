# Certbot + Timeweb DNS-01 manual hook

Скопировать `timeweb.env.example` в `timeweb.env` и заполнить своими данными

```bash
apt update
apt install -y certbot curl jq dnsutils

/root/cerbot/timeweb-certbot-bash.sh run \
  --dry-run \
  --non-interactive \
  --agree-tos \
  -m admin@example.com \
  --cert-name example.com \
  -d example.com \
  -d '*.example.com'
```

Для глубокого поддомена:

```bash
/root/cerbot/timeweb-certbot-bash.sh run \
  --dry-run \
  --non-interactive \
  --agree-tos \
  -m admin@example.com \
  --cert-name subdomain.example.com \
  -d subdomain.example.com \
  -d '*.subdomain.example.com'
```

## Важное

Wildcard лучше всегда брать в кавычки:

```bash
-d '*.example.com'
```

Без кавычек shell может попытаться раскрыть `*` как файловую маску.
