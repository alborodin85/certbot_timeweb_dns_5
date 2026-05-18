# Certbot + Timeweb DNS-01 manual hook

Скрипт `certbot/timeweb-certbot.sh` получает и продлевает wildcard-сертификаты Let's Encrypt через Certbot и DNS-01 challenge в DNS Timeweb.
Эксплуатационная директория на сервере: `/root/certbot`.

Скрипт использует API виртуального хостинга Timeweb:
https://timeweb.com/ru/docs/publichnyj-api-timeweb/metody-api-dlya-virtualnogo-hostinga/.
Для доступа нужны логин Timeweb, пароль и `application token` (`TIMEWEB_APPKEY`). Доступ к DNS API и application token выдаются поддержкой Timeweb после идентификации.
Идентификация требует направления в службу поддержки копии паспорта.

## Что делает скрипт

- работает как `manual-auth-hook`, `manual-cleanup-hook` и `deploy-hook` для обычной команды `certbot`;
- получает временный auth token Timeweb через `/v1.2/access`;
- определяет DNS-зону Timeweb для переданного домена;
- создает две TXT-записи `_acme-challenge...` с `CERTBOT_VALIDATION`: для обычного домена и wildcard;
- после создания второй TXT-записи дожидается появления обеих записей у всех настроенных DNS-резолверов;
- удаляет созданные им TXT-записи после проверки Certbot;
- при следующем запуске для тех же доменов удаляет TXT-записи, которые остались в `state` после прерванного предыдущего запуска;
- пишет краткий собственный лог успешных выпусков/продлений и ошибок.

Certbot сохраняет пути к hook-командам в renewal-конфигурации.
Поэтому после первого успешного выпуска нельзя переносить скрипт в другое место без переоформления сертификата или правки renewal-конфига.

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
Скрипт проверяет это в `auth` hook через данные, которые передает Certbot.

Wildcard нужно брать в кавычки. Без кавычек shell может раскрыть `*` как файловую маску до запуска Certbot.

Для пары обычный домен + wildcard Certbot может вызвать `manual-auth-hook` как два раза подряд, так и один раз, в зависимости от сценария проверки у CA.
Скрипт ориентируется на `CERTBOT_REMAINING_CHALLENGES`: пока у текущего запуска остаются challenge, он только создает TXT-записи; ожидание DNS начинается на последнем `auth` hook.

## Подготовка сервера

```bash
apt update
apt install -y certbot curl jq dnsutils procps
git clone https://github.com/alborodin85/certbot_timeweb_dns_5.git /root/certbot
cd /root/certbot
cp certbot/timeweb.env.example certbot/timeweb.env
chmod 600 certbot/timeweb.env
chmod +x certbot/timeweb-certbot.sh
```

Заполнить `certbot/timeweb.env` по комментариям внутри файла.
Файл настроек должен лежать рядом со скриптом: `/root/certbot/certbot/timeweb.env`.

## Первый выпуск сертификата

В примерах ниже `example.com`, `*.example.com` и `admin@example.com` нужно заменить на реальный домен и email.
Let's Encrypt не выпускает сертификаты для `example.com`, поэтому при запуске примера без замены Certbot остановится до вызова hook-скрипта.

Тестовый запуск для домена второго уровня:

```bash
certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook "/root/certbot/certbot/timeweb-certbot.sh auth" \
  --manual-cleanup-hook "/root/certbot/certbot/timeweb-certbot.sh cleanup" \
  --deploy-hook "/root/certbot/certbot/timeweb-certbot.sh deploy" \
  --agree-tos \
  --dry-run \
  --email admin@example.com \
  -d example.com \
  -d '*.example.com'
```

Боевой выпуск для глубокого поддомена:

```bash
certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook "/root/certbot/certbot/timeweb-certbot.sh auth" \
  --manual-cleanup-hook "/root/certbot/certbot/timeweb-certbot.sh cleanup" \
  --deploy-hook "/root/certbot/certbot/timeweb-certbot.sh deploy" \
  --agree-tos \
  --email admin@example.com \
  -d app.example.com \
  -d '*.app.example.com'
```

Все остальные параметры передаются напрямую в Certbot обычным способом, например `--non-interactive`, `--staging`, `--dry-run`, `--expand`.

После успешного выпуска файлы сертификата будут доступны в стандартном каталоге Let's Encrypt:

```bash
/etc/letsencrypt/live/example.com/fullchain.pem
/etc/letsencrypt/live/example.com/privkey.pem
```

Для поддомена имя каталога обычно соответствует первому домену в сертификате, например `/etc/letsencrypt/live/app.example.com/`.

## Продление

Первый запуск выполняется вручную. Дальше Certbot продлевает сертификат штатным механизмом пакета `certbot` - через systemd timer или cron, в зависимости от системы.
При продлении используется обычная команда:

```bash
certbot renew
```

Проверить сохраненные сертификаты и renewal-конфигурацию можно так:

```bash
certbot certificates
certbot renew --dry-run
```

Если сертификат еще не требует продления, Certbot не вызывает hook'и. Такие проверки в краткий лог скрипта не записываются.

## Состояние и очистка TXT

Скрипт хранит созданные TXT-записи в файле:

```bash
/root/certbot/certbot/state/records.tsv
```

Файл нужен cleanup hook'у, чтобы удалить именно те записи, которые создал скрипт.
Если процесс был прерван до cleanup hook'а, запись остается в `state/records.tsv`.
При следующем выпуске или продлении для тех же доменов скрипт сначала попробует удалить такие оставшиеся TXT-записи, а затем создаст новые.

Служебные маркеры активных запусков находятся в:

```bash
/root/certbot/certbot/state/runs/
```

## Логи и диагностика

Основные источники диагностики:

- стандартные логи Certbot в `/var/log/letsencrypt/`;
- подробный stderr/stdout запуска `timeweb-certbot.sh`;
- краткий лог скрипта `/root/certbot/certbot/timeweb-certbot-summary.log`.

Обычные диагностические сообщения скрипт пишет в stderr. Certbot из-за этого может показывать их как `ran with error output`, даже если hook завершился успешно.
Это не ошибка само по себе: реальную ошибку нужно определять по коду завершения hook'а, строкам с `ERROR` и итоговому сообщению Certbot.

Certbot может показывать вывод hook-скрипта не сразу, а пачкой после завершения очередного hook'а.
Из-за этого во время ожидания DNS может показаться, что процесс завис.
Перед ручным прерыванием стоит подождать как минимум `DNS_WAIT_TIMEOUT + DNS_EXTRA_SLEEP_AFTER_VISIBLE`: это максимальное ожидание появления TXT плюс дополнительная пауза после того, как записи уже видны через настроенные резолверы.

Краткий лог фиксирует успешные выпуски/продления через `deploy-hook` и ошибки самого скрипта.
Попытки `certbot renew`, при которых сертификат еще не истек и hook'и не запускались, в этот лог не попадают.
Ошибки Certbot, которые происходят до запуска `manual-auth-hook`, тоже не попадают в этот лог; их нужно смотреть в `/var/log/letsencrypt/`.

Лог автоматически ограничивается размером 1 МБ: перед дописыванием новой записи удаляются самые старые строки.
Каждая запись занимает одну строку; переносы строк и табы заменяются пробелами, повторяющиеся пробелы сжимаются.

Типовые проверки:

```bash
dig +short @1.1.1.1 TXT _acme-challenge.example.com
dig +short @8.8.8.8 TXT _acme-challenge.example.com
certbot renew --dry-run
```
