#!/usr/bin/env bash

# Скрипт используется Certbot'ом как набор hook-команд для DNS-01 challenge:
#
#   timeweb-certbot.sh auth     - создать TXT-запись перед проверкой домена
#   timeweb-certbot.sh cleanup  - удалить TXT-запись после проверки домена
#   timeweb-certbot.sh deploy   - записать факт успешного выпуска/продления
#
# В обычном сценарии человек запускает `certbot certonly ...`, а Certbot сам
# вызывает этот файл с нужной подкомандой и передает данные challenge через
# переменные окружения: CERTBOT_DOMAIN, CERTBOT_VALIDATION, CERTBOT_ALL_DOMAINS.

# "Строгий режим" bash:
#   -e  завершает скрипт при необработанной ошибке команды;
#   -u  запрещает использовать неинициализированные переменные;
#   -o pipefail делает пайплайн ошибочным, если упала любая команда внутри него.
# Это уменьшает шанс тихо продолжить работу после ошибки API, DNS или парсинга.
set -euo pipefail

# Определяем настоящий путь к файлу, даже если его запустили через symlink.
# Certbot сохраняет hook-команды в renewal-конфиге, поэтому важно понимать,
# где физически лежат env, state и лог.
SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

# Конфигурация всегда лежит рядом со скриптом. Это намеренное ограничение:
# renewal-конфиг Certbot должен ссылаться на стабильное место в /root/cerbot.
ENV_FILE="$SCRIPT_DIR/timeweb.env"

# STATE_FILE хранит созданные TXT-записи: id, DNS-зону, subdomain и value.
# Это нужно cleanup hook'у, чтобы удалить ровно те записи, которые создал скрипт.
STATE_DIR="$SCRIPT_DIR/state"
STATE_FILE="$STATE_DIR/records.tsv"

# RUN_DIR хранит маркеры активных запусков Certbot. Они помогают понять,
# что второй auth hook в том же запуске не должен чистить запись первого hook'а.
RUN_DIR="$STATE_DIR/runs"

# Краткий собственный лог: только успешные deploy и ошибки скрипта.
LOG_FILE="$SCRIPT_DIR/timeweb-certbot.log"
LOG_MAX_BYTES=1048576

# Минимальный TTL DNS-записи, который принимает Timeweb API.
DNS_RECORD_TTL=300

# Базовый URL старого публичного API Timeweb для виртуального хостинга.
API_BASE="https://api.timeweb.ru"

# Обычный подробный вывод. Пишем в stderr, чтобы stdout можно было использовать
# для возвращаемых значений функций, например token или id записи.
log() {
  printf '[timeweb-certbot] %s\n' "$*" >&2
}

rotate_event_log() {
  # Если лога еще нет, ротация не нужна.
  [[ -f "$LOG_FILE" ]] || return 0

  local size tmp
  # wc -c возвращает размер файла в байтах. Если по любой причине прочитать
  # размер не удалось, не мешаем основному сценарию работы Certbot.
  size="$(wc -c < "$LOG_FILE" 2>/dev/null)" || return 0
  [[ "$size" =~ ^[0-9]+$ ]] || return 0

  # Если лог достиг лимита, за один вызов удаляем только одну самую старую
  # строку. Даже если файл пока останется больше 1 МБ, следующие записи
  # постепенно вытеснят старые длинные строки.
  (( size < LOG_MAX_BYTES )) && return 0

  tmp="$(mktemp)" || return 0
  tail -n +2 "$LOG_FILE" > "$tmp" 2>/dev/null || {
    rm -f "$tmp"
    return 0
  }
  mv "$tmp" "$LOG_FILE" 2>/dev/null || {
    rm -f "$tmp"
    return 0
  }
}

event_log() {
  local level="$1"
  shift
  local message="$*"
  local normalized ts

  # Summary-лог должен быть построчным: заменяем переносы строк и табы
  # пробелами, затем сжимаем повторяющиеся пробелы.
  normalized="$(printf '%s' "$message" | tr '\r\n\t' '   ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')" || normalized="$message"
  ts="$(date '+%Y-%m-%dT%H:%M:%S%z')" || ts="unknown-time"

  # Логирование не должно ломать выпуск сертификата. Поэтому все операции
  # с логом заканчиваются `|| return 0` или `|| true`.
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || return 0
  touch "$LOG_FILE" 2>/dev/null || return 0
  chmod 600 "$LOG_FILE" 2>/dev/null || true
  rotate_event_log 2>/dev/null || true
  printf '%s %s %s\n' "$ts" "$level" "$normalized" >> "$LOG_FILE" 2>/dev/null || true
}

fail() {
  # Единая точка аварийного завершения: сообщение видно в stderr и в summary-логе.
  printf '[timeweb-certbot] ERROR: %s\n' "$*" >&2
  event_log "ERROR" "$*"
  exit 1
}

on_error() {
  # trap ERR ловит ошибки, которые не прошли через fail(). Это полезно для
  # неожиданных сбоев вроде ошибки mv, jq или синтаксически корректной, но
  # неуспешной команды под set -e.
  local exit_code="$1"
  local line="$2"
  local command="$3"
  event_log "ERROR" "Необработанная ошибка: команда '$command' завершилась с кодом $exit_code на строке $line"
}

# При любой необработанной ошибке bash подставит код возврата, номер строки
# и текст команды, которая упала.
trap 'on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

load_env() {
  # Все секреты и настройки DNS-ожидания находятся в timeweb.env рядом
  # со скриптом. Если файла нет, дальше идти нельзя.
  [[ -f "$ENV_FILE" ]] || fail "Не найден файл настроек: $ENV_FILE"

  # set -a автоматически экспортирует все переменные, которые будут определены
  # при source. Это удобно, если вложенным процессам тоже понадобятся настройки.
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a

  # Проверяем обязательные доступы к Timeweb. Синтаксис ${VAR:-} безопасен
  # под set -u: если переменная не задана, bash не падает раньше нашей ошибки.
  [[ -n "${TIMEWEB_LOGIN:-}" ]] || fail "TIMEWEB_LOGIN не задан в $ENV_FILE"
  [[ -n "${TIMEWEB_PASSWORD:-}" ]] || fail "TIMEWEB_PASSWORD не задан в $ENV_FILE"
  [[ -n "${TIMEWEB_APPKEY:-}" ]] || fail "TIMEWEB_APPKEY не задан в $ENV_FILE"
  [[ -n "${DNS_RESOLVERS:-}" ]] || fail "DNS_RESOLVERS не задан в $ENV_FILE"
  [[ -n "${DNS_WAIT_TIMEOUT:-}" ]] || fail "DNS_WAIT_TIMEOUT не задан в $ENV_FILE"
  [[ -n "${DNS_WAIT_INTERVAL:-}" ]] || fail "DNS_WAIT_INTERVAL не задан в $ENV_FILE"
  [[ -n "${DNS_EXTRA_SLEEP_AFTER_VISIBLE:-}" ]] || fail "DNS_EXTRA_SLEEP_AFTER_VISIBLE не задан в $ENV_FILE"

  # Готовим служебные файлы. Права 700/600 нужны, потому что в state лежат
  # технические данные выпусков, а рядом с ним находится env с секретами.
  mkdir -p "$STATE_DIR"
  mkdir -p "$RUN_DIR"
  touch "$STATE_FILE"
  chmod 700 "$STATE_DIR" || true
  chmod 700 "$RUN_DIR" || true
  chmod 600 "$STATE_FILE" || true
}

require_hook_cmds() {
  local missing=()

  # Hook'и запускаются Certbot'ом, поэтому проверяем только то, что нужно
  # самому hook'у. Certbot здесь уже есть, иначе он бы нас не вызвал.
  for cmd in curl jq dig ps; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if ((${#missing[@]} > 0)); then
    fail "Не найдены команды: ${missing[*]}. Установи: apt install -y curl jq dnsutils procps"
  fi
}

urlenc() {
  # URL-encoding нужен для логина, домена и зоны в пути API.
  # jq умеет надежно кодировать строку через фильтр @uri.
  jq -nr --arg v "$1" '$v|@uri'
}

get_token() {
  local body token

  # Timeweb API работает в два шага:
  #   1. application key передается в x-app-key;
  #   2. логин/пароль передаются через HTTP Basic Auth;
  #   3. в ответе приходит временный Bearer token для остальных запросов.
  body="$(curl -sS -X POST "$API_BASE/v1.2/access" \
    -H "accept: application/json" \
    -H "x-app-key: $TIMEWEB_APPKEY" \
    -u "$TIMEWEB_LOGIN:$TIMEWEB_PASSWORD")"

  # jq -e возвращает ошибочный код, если фильтр дал null/false.
  # `|| true` не дает set -e сразу завершить скрипт: ниже мы сами покажем
  # понятную ошибку вместе с телом ответа API.
  token="$(printf '%s' "$body" | jq -er '.token // empty')" || true
  [[ -n "$token" ]] || fail "Не удалось получить token из /v1.2/access. Ответ: $body"
  printf '%s' "$token"
}

api_get_status() {
  local url="$1"
  local token="$2"

  # Для проверки существования зоны нам нужен HTTP-код. Тело ответа пишем
  # во временный файл, а код печатаем в stdout через -w '%{http_code}'.
  curl -sS -o /tmp/timeweb-api-body.$$ -w '%{http_code}' \
    -H 'accept: */*' \
    -H "x-app-key: $TIMEWEB_APPKEY" \
    -H "Authorization: Bearer $token" \
    "$url"
}

normalize_domain() {
  local domain="$1"

  # Certbot может передать домен с точкой на конце или wildcard-имя.
  # Для поиска DNS-зоны нужно обычное имя без "*." и финальной точки.
  domain="${domain%.}"
  if [[ "$domain" == \*.* ]]; then
    domain="${domain#*.}"
  fi
  printf '%s' "$domain"
}

find_zone() {
  local domain="$1"
  local token="$2"

  # Разбиваем домен на labels по точкам. Например:
  #   app.example.com -> app / example / com
  # Потом пробуем зоны от более конкретной к менее конкретной:
  #   app.example.com, example.com
  local IFS='.'
  read -r -a labels <<< "$domain"

  local n="${#labels[@]}"
  (( n >= 2 )) || fail "Некорректный домен: $domain"

  local i candidate encoded code url
  for ((i=0; i<=n-2; i++)); do
    # ${labels[*]:i} берет срез массива с позиции i до конца.
    # Внутренний IFS='.' склеивает labels обратно через точку.
    candidate="$(IFS='.'; echo "${labels[*]:i}")"
    encoded="$(urlenc "$candidate")"
    url="$API_BASE/v1.2/accounts/$(urlenc "$TIMEWEB_LOGIN")/domains/$encoded/user-records?limit=1"

    # Если API отдал 200, значит такая DNS-зона есть у аккаунта Timeweb.
    code="$(api_get_status "$url" "$token")" || true
    rm -f /tmp/timeweb-api-body.$$

    if [[ "$code" == "200" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done

  fail "Не удалось определить доменную зону Timeweb для $domain"
}

txt_subdomain() {
  local domain="$1"
  local zone="$2"
  local suffix=".$zone"

  # Для example.com TXT-запись должна называться _acme-challenge.
  if [[ "$domain" == "$zone" ]]; then
    printf '%s' '_acme-challenge'
    return 0
  fi

  # Для app.example.com в зоне example.com поддомен будет
  # _acme-challenge.app.
  if [[ "$domain" != *"$suffix" ]]; then
    fail "Домен '$domain' не относится к зоне '$zone'"
  fi

  local prefix="${domain%"$suffix"}"
  printf '_acme-challenge.%s' "$prefix"
}

create_txt_record() {
  local zone="$1"
  local subdomain="$2"
  local value="$3"
  local token="$4"

  local headers body code location id url payload

  # mktemp создает уникальные временные файлы, чтобы параллельные запуски
  # не перетирали ответы друг друга.
  headers="$(mktemp)"
  body="$(mktemp)"
  url="$API_BASE/v1.2/accounts/$(urlenc "$TIMEWEB_LOGIN")/domains/$(urlenc "$zone")/user-records/"

  # Собираем JSON через jq, а не строковой конкатенацией: так спецсимволы
  # в CERTBOT_VALIDATION безопасно экранируются. --argjson нужен для ttl,
  # потому что API требует integer, а не строку.
  payload="$(
    jq -nc \
      --arg subdomain "$subdomain" \
      --arg value "$value" \
      --argjson ttl "$DNS_RECORD_TTL" \
      '{data:{subdomain:$subdomain,value:$value},ttl:$ttl,type:"TXT"}'
  )"

  # -D сохраняет response headers, -o сохраняет body, -w печатает HTTP-код.
  # Location header часто содержит id созданной DNS-записи.
  code="$(curl -sS -D "$headers" -o "$body" -w '%{http_code}' -X POST "$url" \
    -H 'accept: */*' \
    -H "x-app-key: $TIMEWEB_APPKEY" \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    --data "$payload")" || {
      rm -f "$headers" "$body"
    fail "Ошибка curl при создании TXT-записи"
  }

  # Любой 2xx считаем успехом. Остальное завершаем с телом ответа API.
  if [[ ! "$code" =~ ^2 ]]; then
    local response
    response="$(cat "$body")"
    rm -f "$headers" "$body"
    fail "Timeweb вернул HTTP $code при создании TXT. Ответ: $response"
  fi

  # Пытаемся получить id из Location header: обычно это URL вида .../123/.
  location="$(awk 'BEGIN{IGNORECASE=1} /^location:/ {gsub("\r", ""); print $2}' "$headers" | tail -n1)"
  id="${location%/}"
  id="${id##*/}"

  # Если id не пришел в headers, пробуем распространенные варианты JSON-тела.
  if [[ -z "$id" || ! "$id" =~ ^[0-9]+$ ]]; then
    id="$(jq -r '.id // .record.id // .data.id // empty' < "$body")"
  fi

  # Последний fallback: перечитать список записей и найти созданную по
  # subdomain + value. Это медленнее, но делает скрипт устойчивее к форме ответа.
  if [[ -z "$id" || ! "$id" =~ ^[0-9]+$ ]]; then
    id="$(find_record_id "$zone" "$subdomain" "$value" "$token")"
  fi

  rm -f "$headers" "$body"
  [[ -n "$id" ]] || fail "TXT создана, но не удалось определить id записи"
  printf '%s' "$id"
}

find_record_id() {
  local zone="$1"
  local subdomain="$2"
  local value="$3"
  local token="$4"
  local records url

  # Запрашиваем записи зоны и выбираем TXT с тем же subdomain и value.
  # tail -n1 берет последнюю подходящую запись, если вдруг API вернул несколько.
  url="$API_BASE/v1.2/accounts/$(urlenc "$TIMEWEB_LOGIN")/domains/$(urlenc "$zone")/user-records?limit=100"
  records="$(curl -sS "$url" \
    -H 'accept: */*' \
    -H "x-app-key: $TIMEWEB_APPKEY" \
    -H "Authorization: Bearer $token")"

  printf '%s' "$records" | jq -r \
    --arg subdomain "$subdomain" \
    --arg value "$value" \
    '.[] | select(.type == "TXT" and .data.subdomain == $subdomain and .data.value == $value) | .id' | tail -n1
}

save_state() {
  local id="$1"
  local zone="$2"
  local subdomain="$3"
  local value="$4"

  # TSV проще парсить в bash, чем JSON: read с IFS=$'\t' сразу разложит
  # строку по переменным id/zone/subdomain/value.
  printf '%s\t%s\t%s\t%s\n' "$id" "$zone" "$subdomain" "$value" >> "$STATE_FILE"
}

delete_record() {
  local zone="$1"
  local id="$2"
  local token="$3"
  local url code body

  # Удаление считается успешным и при 404: если записи уже нет, желаемое
  # состояние DNS достигнуто.
  body="$(mktemp)"
  url="$API_BASE/v1.2/accounts/$(urlenc "$TIMEWEB_LOGIN")/domains/$(urlenc "$zone")/user-records/$id/"
  code="$(curl -sS -o "$body" -w '%{http_code}' -X DELETE "$url" \
    -H 'accept: */*' \
    -H "x-app-key: $TIMEWEB_APPKEY" \
    -H "Authorization: Bearer $token")" || true

  if [[ "$code" =~ ^2$|^2[0-9][0-9]$ ]]; then
    rm -f "$body"
    return 0
  fi

  if [[ "$code" == "404" ]]; then
    log "Запись id=$id уже отсутствует"
    rm -f "$body"
    return 0
  fi

  log "Не удалось удалить id=$id, HTTP $code, ответ: $(cat "$body")"
  rm -f "$body"
  return 1
}

cleanup_state_records_for_subdomain() {
  local zone_filter="$1"
  local subdomain_filter="$2"
  local token="$3"
  local reason="$4"
  local tmp id zone subdomain value deleted=0 failed=0

  # Мы не редактируем STATE_FILE "на месте". Вместо этого пишем новый файл tmp,
  # куда попадают только те записи, которые нужно оставить. В конце tmp
  # атомарно заменяет старый state через mv.
  tmp="$(mktemp)"

  while IFS=$'\t' read -r id zone subdomain value; do
    [[ -n "${id:-}" ]] || continue

    # Чистим только записи того же _acme-challenge имени. Это важно:
    # параллельный или другой сертификат не должен потерять свои TXT-записи.
    if [[ "$zone" == "$zone_filter" && "$subdomain" == "$subdomain_filter" ]]; then
      log "Удаляю TXT-запись из state: id=$id, zone=$zone, subdomain=$subdomain, reason=$reason"
      if delete_record "$zone" "$id" "$token"; then
        deleted=$((deleted + 1))
      else
        failed=$((failed + 1))
        printf '%s\t%s\t%s\t%s\n' "$id" "$zone" "$subdomain" "$value" >> "$tmp"
      fi
    else
      printf '%s\t%s\t%s\t%s\n' "$id" "$zone" "$subdomain" "$value" >> "$tmp"
    fi
  done < "$STATE_FILE"

  mv "$tmp" "$STATE_FILE"
  chmod 600 "$STATE_FILE" || true

  if (( deleted > 0 )); then
    log "Удалены оставшиеся TXT-записи: zone=$zone_filter, subdomain=$subdomain_filter, count=$deleted"
  fi

  if (( failed > 0 )); then
    event_log "ERROR" "Не удалось удалить часть оставшихся TXT-записей: zone=$zone_filter subdomain=$subdomain_filter failed=$failed"
  fi
}

wait_dns_visible() {
  local fqdn="$1"
  local value="$2"

  # deadline - абсолютное время окончания ожидания. Так проще считать таймаут,
  # чем накапливать количество попыток.
  local deadline=$(( $(date +%s) + DNS_WAIT_TIMEOUT ))
  local resolver out ok

  log "Жду TXT $fqdn = $value через резолверы: $DNS_RESOLVERS"

  while (( $(date +%s) <= deadline )); do
    # ok=1 означает "пока все хорошо". Если хотя бы один резолвер не видит
    # нужный TXT, ставим ok=0 и ждем следующую попытку.
    ok=1

    for resolver in $DNS_RESOLVERS; do
      out="$(dig +time=5 +tries=1 +short @"$resolver" TXT "$fqdn" 2>/dev/null || true)"

      # dig возвращает TXT в кавычках. tr -d '"' убирает кавычки, а grep -Fqx
      # ищет точное совпадение всей строки без интерпретации value как regexp.
      if ! printf '%s\n' "$out" | tr -d '"' | grep -Fqx "$value"; then
        ok=0
        log "Пока не видно через $resolver. Ответ: ${out:-<empty>}"
        break
      fi
    done

    if [[ "$ok" == "1" ]]; then
      # Даже когда DNS уже виден у наших резолверов, Let's Encrypt может
      # проверить чуть позже или через другой путь кешей, поэтому держим
      # дополнительную паузу.
      log "TXT уже виден через все резолверы. Жду еще ${DNS_EXTRA_SLEEP_AFTER_VISIBLE} сек."
      sleep "$DNS_EXTRA_SLEEP_AFTER_VISIBLE"
      return 0
    fi

    sleep "$DNS_WAIT_INTERVAL"
  done

  fail "TXT $fqdn не появился через все резолверы за ${DNS_WAIT_TIMEOUT} сек."
}

split_domain_list() {
  # CERTBOT_ALL_DOMAINS может выглядеть как строка с пробелами, а в некоторых
  # сценариях удобно поддержать еще и запятые. На выходе заполняем bash-массив.
  local -n out_ref=$1
  local value="${2:-}"
  local part

  value="${value//,/ }"
  for part in $value; do
    part="${part//[[:space:]]/}"
    [[ -n "$part" ]] && out_ref+=("$part")
  done
}

validate_certbot_domain_pair() {
  # Наш сценарий сознательно ограничен парой:
  #   example.com + *.example.com
  # Это упрощает state, cleanup и ожидание DNS. Ошибку показываем в auth hook,
  # потому что именно там Certbot передает CERTBOT_ALL_DOMAINS.
  [[ -n "${CERTBOT_ALL_DOMAINS:-}" ]] || fail "Certbot не передал CERTBOT_ALL_DOMAINS; невозможно проверить пару обычный домен + wildcard"

  local domains=()
  split_domain_list domains "$CERTBOT_ALL_DOMAINS"

  if ((${#domains[@]} != 2)); then
    fail "Нужно указать ровно два домена: обычный и wildcard. Certbot передал: ${#domains[@]} (${domains[*]:-нет})"
  fi

  local a="${domains[0]%.}"
  local b="${domains[1]%.}"
  local plain wildcard

  # Принимаем любой порядок - обычный домен первым или wildcard первым.
  if [[ "$a" == \*.* && "$b" != \*.* ]]; then
    wildcard="$a"
    plain="$b"
  elif [[ "$b" == \*.* && "$a" != \*.* ]]; then
    wildcard="$b"
    plain="$a"
  else
    fail "Пара доменов должна быть вида example.com и *.example.com. Сейчас: $a, $b"
  fi

  # ${wildcard#*.} удаляет минимальный префикс до первой точки, то есть
  # превращает *.example.com в example.com.
  if [[ "${wildcard#*.}" != "$plain" ]]; then
    fail "Wildcard и обычный домен не совпадают: $plain и $wildcard"
  fi

  log "Пара доменов проверена: $plain + $wildcard"
}

process_is_certbot() {
  local pid="$1"
  local comm args

  # Нам нужно отличить реальный родительский certbot от нашего скрипта,
  # в пути которого тоже есть слово certbot. Поэтому сначала смотрим имя
  # исполняемого файла (comm), а потом аккуратно проверяем argv.
  comm="$(ps -p "$pid" -o comm= 2>/dev/null | tr -d '[:space:]' || true)"
  args="$(ps -p "$pid" -o args= 2>/dev/null || true)"

  [[ "$comm" == "certbot" ]] || [[ "$args" =~ (^|[[:space:]])([^[:space:]]*/)?certbot([[:space:]]|$) ]]
}

certbot_parent_pid() {
  # Hook запускается не всегда прямым дочерним процессом certbot: между ними
  # может быть shell. Поэтому идем вверх по PPID, пока не найдем certbot.
  local pid="$PPID"
  local next_pid

  while [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]]; do
    if process_is_certbot "$pid"; then
      printf '%s' "$pid"
      return 0
    fi

    next_pid="$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d '[:space:]' || true)"
    [[ -n "$next_pid" && "$next_pid" != "$pid" ]] || break
    pid="$next_pid"
  done

  printf '%s' "$PPID"
}

run_marker_for_subdomain() {
  local zone="$1"
  local subdomain="$2"
  local raw="$zone $subdomain"
  local key

  # Имя marker-файла строится из зоны и subdomain. Так оба challenge,
  # которые используют один и тот же _acme-challenge, видят один marker.
  # tr -cd оставляет только безопасные символы для имени файла.
  key="$(printf '%s' "$raw" | tr ' ,*/' '____' | tr -cd 'A-Za-z0-9_.-')"
  [[ -n "$key" ]] || key="unknown"
  printf '%s/%s.active' "$RUN_DIR" "$key"
}

marker_pid_is_active() {
  local marker="$1"
  local pid

  # Marker считается живым только если в первой строке есть PID и этот PID
  # сейчас принадлежит процессу certbot. Если процесс завершился, marker старый.
  [[ -f "$marker" ]] || return 1
  read -r pid < "$marker" || return 1
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1

  process_is_certbot "$pid"
}

prepare_domain_run() {
  local zone="$1"
  local subdomain="$2"
  local token="$3"
  local marker pid

  # Первый auth hook нового запуска чистит старые записи из state для того же
  # имени _acme-challenge. Второй auth hook того же запуска marker уже увидит
  # и не станет удалять только что созданную запись первого challenge.
  marker="$(run_marker_for_subdomain "$zone" "$subdomain")"
  if marker_pid_is_active "$marker"; then
    return 0
  fi

  cleanup_state_records_for_subdomain "$zone" "$subdomain" "$token" "stale-before-new-run"

  # Сохраняем PID certbot и немного диагностической информации. Само наличие
  # marker-файла не важно; важен живой PID внутри него.
  pid="$(certbot_parent_pid)"
  printf '%s\n%s\n%s\n' "$pid" "$(date '+%Y-%m-%dT%H:%M:%S%z')" "${CERTBOT_ALL_DOMAINS:-}" > "$marker"
  chmod 600 "$marker" || true
}

cmd_auth() {
  # manual-auth-hook.
  #
  # Certbot вызывает его до проверки домена Let's Encrypt. В этот момент
  # Certbot уже знает validation token и передает его через CERTBOT_VALIDATION.
  # Задача hook'а: создать TXT-запись и дождаться ее видимости в DNS.
  load_env
  require_hook_cmds

  local identifier validation domain token zone subdomain fqdn id

  # В разных версиях/режимах Certbot имя домена может быть в CERTBOT_IDENTIFIER
  # или CERTBOT_DOMAIN. Берем первый доступный вариант.
  identifier="${CERTBOT_IDENTIFIER:-${CERTBOT_DOMAIN:-}}"
  validation="${CERTBOT_VALIDATION:-}"
  [[ -n "$identifier" ]] || fail "Certbot не передал CERTBOT_DOMAIN/CERTBOT_IDENTIFIER"
  [[ -n "$validation" ]] || fail "Certbot не передал CERTBOT_VALIDATION"

  validate_certbot_domain_pair

  domain="$(normalize_domain "$identifier")"
  token="$(get_token)"
  zone="$(find_zone "$domain" "$token")"
  subdomain="$(txt_subdomain "$domain" "$zone")"
  fqdn="$subdomain.$zone"

  # Перед созданием новой TXT-записи чистим старые state-записи для того же
  # fqdn, но только один раз на запуск Certbot.
  prepare_domain_run "$zone" "$subdomain" "$token"

  log "Создаю TXT: zone=$zone, subdomain=$subdomain, fqdn=$fqdn"
  id="$(create_txt_record "$zone" "$subdomain" "$validation" "$token")"
  save_state "$id" "$zone" "$subdomain" "$validation"
  log "Создана TXT-запись id=$id"

  wait_dns_visible "$fqdn" "$validation"
}

cmd_cleanup() {
  # manual-cleanup-hook.
  #
  # Certbot вызывает его после проверки challenge. Даже если проверка домена
  # не прошла, cleanup обычно все равно вызывается, и мы удаляем TXT-запись.
  load_env
  require_hook_cmds

  local validation token tmp id zone subdomain value found=0 failed=0
  validation="${CERTBOT_VALIDATION:-}"
  [[ -n "$validation" ]] || fail "Certbot не передал CERTBOT_VALIDATION"
  token="$(get_token)"
  tmp="$(mktemp)"

  # Ищем в state строки с тем же validation token, который Certbot сейчас
  # просит убрать. Успешно удаленные записи в новый state не попадают.
  while IFS=$'\t' read -r id zone subdomain value; do
    [[ -n "${id:-}" ]] || continue
    if [[ "$value" == "$validation" ]]; then
      found=1
      log "Удаляю TXT-запись id=$id, zone=$zone, subdomain=$subdomain"
      if ! delete_record "$zone" "$id" "$token"; then
        failed=$((failed + 1))
        printf '%s\t%s\t%s\t%s\n' "$id" "$zone" "$subdomain" "$value" >> "$tmp"
      fi
    else
      printf '%s\t%s\t%s\t%s\n' "$id" "$zone" "$subdomain" "$value" >> "$tmp"
    fi
  done < "$STATE_FILE"

  mv "$tmp" "$STATE_FILE"
  chmod 600 "$STATE_FILE" || true

  # Если записи нет, это не фатально: возможно, она уже была удалена вручную
  # или предыдущая попытка cleanup дошла до удаления, но не обновила state.
  if [[ "$found" == "0" ]]; then
    log "В state-файле не найдена запись для текущего CERTBOT_VALIDATION. Пробую ничего не делать."
  fi

  if (( failed > 0 )); then
    event_log "ERROR" "Cleanup hook не смог удалить TXT-записи для текущего CERTBOT_VALIDATION: failed=$failed"
  fi
}

cmd_deploy() {
  # deploy-hook.
  #
  # Certbot вызывает его только после успешного выпуска или продления
  # сертификата. Это правильное место для краткого лога "сертификат обновлен".
  local renewed_lineage="${RENEWED_LINEAGE:-unknown}"
  local renewed_domains="${RENEWED_DOMAINS:-unknown}"

  log "Сертификат успешно получен или продлен: domains=$renewed_domains, lineage=$renewed_lineage"
  event_log "OK" "Сертификат успешно получен или продлен: domains=$renewed_domains lineage=$renewed_lineage"
}

case "${1:-}" in
  # Первый аргумент выбирает режим работы. Человек обычно не вызывает эти
  # команды руками; их вызывает Certbot из --manual-auth-hook,
  # --manual-cleanup-hook и --deploy-hook.
  auth)
    cmd_auth
    ;;
  cleanup)
    cmd_cleanup
    ;;
  deploy)
    cmd_deploy
    ;;
  *)
    cat >&2 <<USAGE
Использование:
  $0 auth      # вызывается certbot'ом
  $0 cleanup   # вызывается certbot'ом
  $0 deploy    # вызывается certbot'ом после успешного выпуска/продления
USAGE
    exit 2
    ;;
esac
