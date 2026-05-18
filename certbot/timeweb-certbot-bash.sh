#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
ENV_FILE="${TIMEWEB_ENV_FILE:-$SCRIPT_DIR/timeweb.env}"
STATE_DIR="${TIMEWEB_STATE_DIR:-$SCRIPT_DIR/state}"
STATE_FILE="$STATE_DIR/records.tsv"
API_BASE="https://api.timeweb.ru"

log() {
  printf '[timeweb-certbot] %s\n' "$*" >&2
}

fail() {
  printf '[timeweb-certbot] ERROR: %s\n' "$*" >&2
  exit 1
}

load_env() {
  [[ -f "$ENV_FILE" ]] || fail "Не найден файл настроек: $ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a

  : "${TIMEWEB_LOGIN:?TIMEWEB_LOGIN не задан в $ENV_FILE}"
  : "${TIMEWEB_PASSWORD:?TIMEWEB_PASSWORD не задан в $ENV_FILE}"
  : "${TIMEWEB_APPKEY:?TIMEWEB_APPKEY не задан в $ENV_FILE}"

  DNS_RESOLVERS="${DNS_RESOLVERS:-1.1.1.1 8.8.8.8}"
  DNS_WAIT_TIMEOUT="${DNS_WAIT_TIMEOUT:-300}"
  DNS_WAIT_INTERVAL="${DNS_WAIT_INTERVAL:-10}"
  DNS_EXTRA_SLEEP_AFTER_VISIBLE="${DNS_EXTRA_SLEEP_AFTER_VISIBLE:-60}"

  mkdir -p "$STATE_DIR"
  touch "$STATE_FILE"
  chmod 700 "$STATE_DIR" || true
  chmod 600 "$STATE_FILE" || true
}

require_cmds() {
  local missing=()
  for cmd in curl jq dig certbot; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if ((${#missing[@]} > 0)); then
    fail "Не найдены команды: ${missing[*]}. Установи: apt install -y certbot curl jq dnsutils"
  fi
}

require_hook_cmds() {
  local missing=()
  for cmd in curl jq dig; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if ((${#missing[@]} > 0)); then
    fail "Не найдены команды: ${missing[*]}. Установи: apt install -y curl jq dnsutils"
  fi
}

urlenc() {
  jq -nr --arg v "$1" '$v|@uri'
}

get_token() {
  local body token
  body="$(curl -sS -X POST "$API_BASE/v1.2/access" \
    -H "accept: application/json" \
    -H "x-app-key: $TIMEWEB_APPKEY" \
    -u "$TIMEWEB_LOGIN:$TIMEWEB_PASSWORD")"

  token="$(printf '%s' "$body" | jq -er '.token // empty')" || true
  [[ -n "$token" ]] || fail "Не удалось получить token из /v1.2/access. Ответ: $body"
  printf '%s' "$token"
}

api_get_status() {
  local url="$1"
  local token="$2"
  curl -sS -o /tmp/timeweb-api-body.$$ -w '%{http_code}' \
    -H 'accept: */*' \
    -H "x-app-key: $TIMEWEB_APPKEY" \
    -H "Authorization: Bearer $token" \
    "$url"
}

normalize_domain() {
  local domain="$1"
  domain="${domain%.}"
  if [[ "$domain" == \*.* ]]; then
    domain="${domain#*.}"
  fi
  printf '%s' "$domain"
}

find_zone() {
  local domain="$1"
  local token="$2"
  local IFS='.'
  read -r -a labels <<< "$domain"

  local n="${#labels[@]}"
  (( n >= 2 )) || fail "Некорректный домен: $domain"

  local i candidate encoded code url
  for ((i=0; i<=n-2; i++)); do
    candidate="$(IFS='.'; echo "${labels[*]:i}")"
    encoded="$(urlenc "$candidate")"
    url="$API_BASE/v1.2/accounts/$(urlenc "$TIMEWEB_LOGIN")/domains/$encoded/user-records?limit=1"
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

  if [[ "$domain" == "$zone" ]]; then
    printf '%s' '_acme-challenge'
    return 0
  fi

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
  headers="$(mktemp)"
  body="$(mktemp)"
  url="$API_BASE/v1.2/accounts/$(urlenc "$TIMEWEB_LOGIN")/domains/$(urlenc "$zone")/user-records/"
  payload="$(jq -nc --arg subdomain "$subdomain" --arg value "$value" '{data:{subdomain:$subdomain,value:$value},type:"TXT"}')"

  code="$(curl -sS -D "$headers" -o "$body" -w '%{http_code}' -X POST "$url" \
    -H 'accept: */*' \
    -H "x-app-key: $TIMEWEB_APPKEY" \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    --data "$payload")" || {
      rm -f "$headers" "$body"
      fail "Ошибка curl при создании TXT-записи"
    }

  if [[ ! "$code" =~ ^2 ]]; then
    local response
    response="$(cat "$body")"
    rm -f "$headers" "$body"
    fail "Timeweb вернул HTTP $code при создании TXT. Ответ: $response"
  fi

  location="$(awk 'BEGIN{IGNORECASE=1} /^location:/ {gsub("\r", ""); print $2}' "$headers" | tail -n1)"
  id="${location%/}"
  id="${id##*/}"

  if [[ -z "$id" || ! "$id" =~ ^[0-9]+$ ]]; then
    id="$(jq -r '.id // .record.id // .data.id // empty' < "$body")"
  fi

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
  printf '%s\t%s\t%s\t%s\n' "$id" "$zone" "$subdomain" "$value" >> "$STATE_FILE"
}

delete_record() {
  local zone="$1"
  local id="$2"
  local token="$3"
  local url code body
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

wait_dns_visible() {
  local fqdn="$1"
  local value="$2"
  local deadline=$(( $(date +%s) + DNS_WAIT_TIMEOUT ))
  local resolver out ok

  log "Жду TXT $fqdn = $value через резолверы: $DNS_RESOLVERS"

  while (( $(date +%s) <= deadline )); do
    ok=1

    for resolver in $DNS_RESOLVERS; do
      out="$(dig +time=5 +tries=1 +short @"$resolver" TXT "$fqdn" 2>/dev/null || true)"
      if ! printf '%s\n' "$out" | tr -d '"' | grep -Fqx "$value"; then
        ok=0
        log "Пока не видно через $resolver. Ответ: ${out:-<empty>}"
        break
      fi
    done

    if [[ "$ok" == "1" ]]; then
      log "TXT уже виден через все резолверы. Жду еще ${DNS_EXTRA_SLEEP_AFTER_VISIBLE} сек."
      sleep "$DNS_EXTRA_SLEEP_AFTER_VISIBLE"
      return 0
    fi

    sleep "$DNS_WAIT_INTERVAL"
  done

  fail "TXT $fqdn не появился через все резолверы за ${DNS_WAIT_TIMEOUT} сек."
}

collect_domains_from_args() {
  local -n out_ref=$1
  shift
  local arg value part
  while (($#)); do
    arg="$1"
    case "$arg" in
      -d|--domain|--domains)
        shift || fail "После $arg должен быть домен"
        value="${1:-}"
        IFS=',' read -ra parts <<< "$value"
        for part in "${parts[@]}"; do
          part="${part//[[:space:]]/}"
          [[ -n "$part" ]] && out_ref+=("$part")
        done
        ;;
      --domain=*|--domains=*)
        value="${arg#*=}"
        IFS=',' read -ra parts <<< "$value"
        for part in "${parts[@]}"; do
          part="${part//[[:space:]]/}"
          [[ -n "$part" ]] && out_ref+=("$part")
        done
        ;;
    esac
    shift || true
  done
}

validate_domain_pair() {
  local domains=()
  collect_domains_from_args domains "$@"

  if ((${#domains[@]} != 2)); then
    fail "Нужно указать ровно два домена через -d: обычный и wildcard. Найдено: ${#domains[@]} (${domains[*]:-нет})"
  fi

  local a="${domains[0]%.}"
  local b="${domains[1]%.}"
  local plain wildcard

  if [[ "$a" == \*.* && "$b" != \*.* ]]; then
    wildcard="$a"
    plain="$b"
  elif [[ "$b" == \*.* && "$a" != \*.* ]]; then
    wildcard="$b"
    plain="$a"
  else
    fail "Пара доменов должна быть вида example.com и *.example.com. Сейчас: $a, $b"
  fi

  if [[ "${wildcard#*.}" != "$plain" ]]; then
    fail "Wildcard и обычный домен не совпадают: $plain и $wildcard"
  fi

  log "Пара доменов проверена: $plain + $wildcard"
}

cmd_run() {
  require_cmds
  validate_domain_pair "$@"

  exec certbot certonly \
    --manual \
    --preferred-challenges dns \
    --manual-auth-hook "$SCRIPT_PATH auth" \
    --manual-cleanup-hook "$SCRIPT_PATH cleanup" \
    "$@"
}

cmd_auth() {
  load_env
  require_hook_cmds

  local identifier validation domain token zone subdomain fqdn id
  identifier="${CERTBOT_IDENTIFIER:-${CERTBOT_DOMAIN:-}}"
  validation="${CERTBOT_VALIDATION:-}"
  [[ -n "$identifier" ]] || fail "Certbot не передал CERTBOT_DOMAIN/CERTBOT_IDENTIFIER"
  [[ -n "$validation" ]] || fail "Certbot не передал CERTBOT_VALIDATION"

  domain="$(normalize_domain "$identifier")"
  token="$(get_token)"
  zone="$(find_zone "$domain" "$token")"
  subdomain="$(txt_subdomain "$domain" "$zone")"
  fqdn="$subdomain.$zone"

  log "Создаю TXT: zone=$zone, subdomain=$subdomain, fqdn=$fqdn"
  id="$(create_txt_record "$zone" "$subdomain" "$validation" "$token")"
  save_state "$id" "$zone" "$subdomain" "$validation"
  log "Создана TXT-запись id=$id"

  wait_dns_visible "$fqdn" "$validation"
}

cmd_cleanup() {
  load_env
  require_hook_cmds

  local validation token tmp id zone subdomain value found=0
  validation="${CERTBOT_VALIDATION:-}"
  [[ -n "$validation" ]] || fail "Certbot не передал CERTBOT_VALIDATION"
  token="$(get_token)"
  tmp="$(mktemp)"

  while IFS=$'\t' read -r id zone subdomain value; do
    [[ -n "${id:-}" ]] || continue
    if [[ "$value" == "$validation" ]]; then
      found=1
      log "Удаляю TXT-запись id=$id, zone=$zone, subdomain=$subdomain"
      delete_record "$zone" "$id" "$token" || true
    else
      printf '%s\t%s\t%s\t%s\n' "$id" "$zone" "$subdomain" "$value" >> "$tmp"
    fi
  done < "$STATE_FILE"

  mv "$tmp" "$STATE_FILE"
  chmod 600 "$STATE_FILE" || true

  if [[ "$found" == "0" ]]; then
    log "В state-файле не найдена запись для текущего CERTBOT_VALIDATION. Пробую ничего не делать."
  fi
}

case "${1:-}" in
  run)
    shift
    cmd_run "$@"
    ;;
  auth)
    cmd_auth
    ;;
  cleanup)
    cmd_cleanup
    ;;
  *)
    cat >&2 <<USAGE
Использование:
  $0 run [опции certbot] -d example.com -d '*.example.com'
  $0 auth      # вызывается certbot'ом
  $0 cleanup   # вызывается certbot'ом
USAGE
    exit 2
    ;;
esac
