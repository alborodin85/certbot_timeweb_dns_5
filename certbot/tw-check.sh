#!/usr/bin/env bash
set -u
. /root/certbot/certbot/timeweb.env
A=https://api.timeweb.ru
L=$(jq -rn --arg s "$TIMEWEB_LOGIN" '$s|@uri')
C=(-sS --max-time 30)
TOKEN=$(curl "${C[@]}" -X POST "$A/v1.2/access" -H "accept: application/json" -H "x-app-key: $TIMEWEB_APPKEY" -u "$TIMEWEB_LOGIN:$TIMEWEB_PASSWORD" | jq -r '.token // empty')
[ -n "$TOKEN" ] || { echo "токен не получен"; exit 1; }
H=(-H "accept: */*" -H "x-app-key: $TIMEWEB_APPKEY" -H "Authorization: Bearer $TOKEN")
recs() { curl "${C[@]}" "${H[@]}" "$A/v1.2/accounts/$L/domains/$1/user-records?limit=100"; }
addtxt() {  # $1 домен, $2 поддомен
  curl "${C[@]}" -o /tmp/tw.json -w '%{http_code}' -X POST "${H[@]}" -H "Content-Type: application/json" \
    "$A/v1.2/accounts/$L/domains/$1/user-records/" \
    -d "{\"data\":{\"subdomain\":\"$2\",\"value\":\"tw-check-test\"},\"ttl\":300,\"type\":\"TXT\"}"
}
ok() { [ "$1" = 200 ] || [ "$1" = 201 ]; }

echo "== TXT-записи в it5.su, связанные с acme/admin24:"
recs it5.su | jq -r '.[]? | select(.type=="TXT") | select((.data.subdomain // "") | test("acme|admin24")) | "   \(.id) sub=\(.data.subdomain) val=\(.data.value)"'

c=$(addtxt it5.su _acme-challenge.admin24); echo "== 1) it5.su + _acme-challenge.admin24 -> HTTP $c $(head -c 150 /tmp/tw.json)"
if ! ok "$c"; then
  c=$(addtxt admin24.it5.su _acme-challenge); echo "== 2) admin24.it5.su + _acme-challenge -> HTTP $c $(head -c 150 /tmp/tw.json)"
fi
if ! ok "$c"; then
  s=$(curl "${C[@]}" -o /tmp/tw2.json -w '%{http_code}' -X POST "${H[@]}" "$A/v1.1/accounts/$L/domains/it5.su/subdomains/_acme-challenge.admin24")
  echo "== 3a) создание поддомена _acme-challenge.admin24 -> HTTP $s $(head -c 150 /tmp/tw2.json)"
  c=$(addtxt it5.su _acme-challenge.admin24); echo "== 3b) повтор способа 1 -> HTTP $c $(head -c 150 /tmp/tw.json)"
fi

echo "== удаляю тестовые записи:"
for z in it5.su admin24.it5.su; do
  for id in $(recs "$z" | jq -r '.[]? | select(.type=="TXT" and .data.value=="tw-check-test") | .id' 2>/dev/null); do
    echo "   $z $id -> HTTP $(curl "${C[@]}" -o /dev/null -w '%{http_code}' -X DELETE "${H[@]}" "$A/v1.2/accounts/$L/domains/$z/user-records/$id/")"
  done
done
