# Certbot + Timeweb DNS-01 manual hook

Скрипт `timeweb-certbot.sh` получает и продлевает wildcard-сертификаты Let's Encrypt через Certbot и DNS-01 challenge в DNS Timeweb.
Эксплуатационная директория на сервере: `/root/cerbot`. Все команды ниже приведены относительно нее, хотя править файлы можно в текущей рабочей копии проекта.

Скрипт использует API виртуального хостинга Timeweb:
https://timeweb.com/ru/docs/publichnyj-api-timeweb/metody-api-dlya-virtualnogo-hostinga/.
Для доступа нужны логин Timeweb, пароль и `application token` (`TIMEWEB_APPKEY`). Доступ к DNS API и application token выдаются поддержкой Timeweb после идентификации.

## Что делает скрипт

- запускает `certbot certonly --manual --preferred-challenges dns`;
- передает Certbot'у `--manual-auth-hook` и `--manual-cleanup-hook`;
- получает временный auth token Timeweb через `/v1.2/access`;
- определяет DNS-зону Timeweb для переданного домена;
- создает TXT-запись `_acme-challenge...` с `CERTBOT_VALIDATION`;
- ждет, пока TXT появится у всех настроенных DNS-резолверов;
- после проверки Certbot удаляет созданную TXT-запись через cleanup hook.

Certbot сохраняет пути к manual hook'ам в renewal-конфигурации. Поэтому после первого успешного выпуска нельзя переносить скрипт в другое место без переоформления или правки renewal-конфига.

## Ограничения по доменам

За один запуск нужно передать ровно два домена:

- обычный домен;
- wildcard для того же домена.

Примеры допустимых пар:

```bash
-d example.com -d '*.example.com'
-d app.example.com -d '*.app.example.com'
```

Недопустимо передавать только wildcard, больше двух доменов или несовпадающую пару вроде `example.com` и `*.app.example.com`.

Wildcard нужно брать в кавычки. Без кавычек shell может раскрыть `*` как файловую маску до запуска скрипта.

## Подготовка сервера

```bash
apt update
apt install -y certbot curl jq dnsutils
cd /root/cerbot
cp certbot/timeweb.env.example certbot/timeweb.env
chmod 600 certbot/timeweb.env
chmod +x certbot/timeweb-certbot.sh
```

Заполнить `certbot/timeweb.env`:

```bash
TIMEWEB_LOGIN="your_login"
TIMEWEB_PASSWORD="your_timeweb_password"
TIMEWEB_APPKEY="your_timeweb_app_key"
```

Опциональные настройки DNS-ожидания:

```bash
DNS_RESOLVERS="1.1.1.1 8.8.8.8"
DNS_WAIT_TIMEOUT="300"
DNS_WAIT_INTERVAL="10"
DNS_EXTRA_SLEEP_AFTER_VISIBLE="60"
```

По умолчанию `timeweb.env` должен лежать рядом со скриптом. При необходимости путь можно переопределить переменной `TIMEWEB_ENV_FILE`, а каталог состояния - `TIMEWEB_STATE_DIR`.

## Первый выпуск сертификата

Для домена второго уровня:

```bash
/root/cerbot/certbot/timeweb-certbot.sh run \
  --agree-tos \
  --email admin@example.com \
  -d example.com \
  -d '*.example.com'
```

Для глубокого поддомена:

```bash
/root/cerbot/certbot/timeweb-certbot.sh run \
  --agree-tos \
  --email admin@example.com \
  -d app.example.com \
  -d '*.app.example.com'
```

Все параметры после `run` передаются в Certbot. Например, можно добавлять `--non-interactive`, `--staging`, `--dry-run`, `--expand` и другие опции Certbot.

После успешного выпуска файлы сертификата будут доступны в стандартном каталоге Let's Encrypt:

```bash
/etc/letsencrypt/live/example.com/fullchain.pem
/etc/letsencrypt/live/example.com/privkey.pem
```

Для поддомена имя каталога обычно соответствует первому домену в сертификате, например `/etc/letsencrypt/live/app.example.com/`.

## Продление

Первый запуск выполняется вручную. Дальше Certbot продлевает сертификат штатным механизмом пакета `certbot` - через systemd timer или cron, в зависимости от системы.
При продлении Certbot использует сохраненные hook-команды:

```bash
/root/cerbot/certbot/timeweb-certbot.sh auth
/root/cerbot/certbot/timeweb-certbot.sh cleanup
```

Проверить renewal-конфигурацию можно так:

```bash
certbot certificates
certbot renew --dry-run
```

## Состояние и очистка TXT

Скрипт хранит созданные TXT-записи в файле:

```bash
/root/cerbot/certbot/state/records.tsv
```

Файл нужен cleanup hook'у, чтобы удалить именно те записи, которые создал текущий запуск. Права на каталог `state` и файл состояния скрипт выставляет автоматически.

Если процесс был прерван до cleanup hook'а, TXT-запись может остаться в DNS Timeweb. В этом случае ее нужно удалить вручную в панели Timeweb или через API, а затем проверить `state/records.tsv`.

## Логи и диагностика

Основные источники диагностики:

- stderr/stdout запуска `timeweb-certbot.sh`;
- стандартные логи Certbot в `/var/log/letsencrypt/`;
- renewal-конфиги в `/etc/letsencrypt/renewal/`.

В текущей версии скрипта отдельный собственный лог-файл не ведется: сообщения выводятся в консоль и попадают в логи того механизма, который запускает Certbot.

Типовые проверки:

```bash
dig +short @1.1.1.1 TXT _acme-challenge.example.com
dig +short @8.8.8.8 TXT _acme-challenge.example.com
certbot renew --dry-run
```
