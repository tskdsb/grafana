#!/usr/bin/env bash
# Does the cap actually refuse anything?
#
# Everything else verifies the cap staying out of the way. This verifies the
# one behaviour the feature exists for, against a live server with a real limit
# configured, which no unit test covers: the identity, the path, the moment the
# response completes and the slot is returned are all real here.

set -uo pipefail

GRAFANA="${GRAFANA:-https://ml-maas.bytedance.net/cn-beijing-boe/grafana}"
AUTH="${AUTH:-admin:prom-operator}"
DS_UID="${DS_UID:-b6699235-9888-4161-80bc-ec9e0024579f}"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
note() { printf '        %s\n' "$1"; }

api() { curl -s -u "$AUTH" "$@"; }

has() {
  local n
  n=$(printf '%s' "$1" | grep -c -- "$2")
  [ "${n:-0}" -gt 0 ]
}

# Case-insensitive variant. Needed separately because has() passes everything
# after the haystack as the pattern, so `has "$x" -i "foo"` searches for the
# literal "-i" -- which is how this script reported a Retry-After header that
# the server never sends.
hasi() {
  local n
  n=$(printf '%s' "$1" | grep -ci -- "$2")
  [ "${n:-0}" -gt 0 ]
}

metric() {
  api "$GRAFANA/metrics" 2>/dev/null \
    | awk -v m="$1" '$0 ~ "^"m"[ {]" { s += $NF } END { printf "%.0f", s+0 }'
}

# A query slow enough to still be running when the next one arrives, without
# being so large the backend refuses it outright.
#
# The first attempt grouped by three labels over a day and came back 400,
# "not enough memory for incremental aggregation ... maxMemoryPerQuery" -- a
# backend limit, nothing to do with the cap, but it meant those requests never
# reached the state this is trying to observe. Aggregating without the by()
# keeps the series count low while the range still costs real time.
heavy() {
  local out="$1" now; now=$(date +%s)
  local code
  code=$(curl -s -u "$AUTH" -o /dev/null -w '%{http_code}' \
    -X POST "$GRAFANA/api/ds/query" -H 'Content-Type: application/json' \
    -d "{\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"$DS_UID\",\"type\":\"prometheus\"},\"expr\":\"sum(rate(container_cpu_usage_seconds_total[5m]))\",\"range\":true,\"instant\":false,\"intervalMs\":1000,\"maxDataPoints\":20000}],\"from\":\"$(( (now-86400) * 1000 ))\",\"to\":\"$(( now * 1000 ))\"}" \
    2>/dev/null)
  printf '%s' "$code" > "$out"
}

echo "==============================================="
echo " does the cap refuse anything"
echo "==============================================="
echo

# --- configuration under test ---------------------------------------------
S=$(api "$GRAFANA/api/admin/datasource-rate-limits/stats")
CFG=$(printf '%s' "$S" | python3 -c '
import json,sys
c = (json.load(sys.stdin).get("concurrency") or {})
print("%s %s %s" % (c.get("enforcing"), c.get("limit"), c.get("recording")))
' 2>/dev/null)
ENFORCING=$(echo "$CFG" | cut -d' ' -f1)
LIMIT=$(echo "$CFG" | cut -d' ' -f2)
note "enforcing=$ENFORCING limit=$LIMIT"

if [ "$ENFORCING" != "True" ]; then
  bad "the cap is not enforcing -- nothing below would prove anything"
  echo
  printf ' %d passed, %d failed\n' "$PASS" "$FAIL"
  exit 1
fi
ok "cap is enforcing with limit=$LIMIT"
echo

# --- 1. beyond the limit, requests are refused ----------------------------
echo "[1] concurrent requests past the limit get 429"
DEN_BEFORE=$(metric grafana_datasource_ratelimit_concurrency_denied_total)

TMP=$(mktemp -d)
N=$(( LIMIT + 3 ))
for i in $(seq 1 "$N"); do
  heavy "$TMP/$i" &
done
wait

CODES=""
N200=0; N429=0; NOTHER=0
for i in $(seq 1 "$N"); do
  c=$(cat "$TMP/$i" 2>/dev/null)
  CODES="$CODES $c"
  case "$c" in
    200) N200=$((N200+1)) ;;
    429) N429=$((N429+1)) ;;
    *)   NOTHER=$((NOTHER+1)) ;;
  esac
done
rm -rf "$TMP"
note "fired $N at once -> $CODES"
note "200: $N200   429: $N429   other: $NOTHER"

if [ "$N429" -gt 0 ]; then
  ok "$N429 of $N were refused"
else
  bad "nothing was refused with $N concurrent requests against a limit of $LIMIT -- "\
"either they did not overlap, or the cap is not holding"
fi
if [ "$N200" -gt 0 ]; then
  ok "$N200 were served: the cap refuses the excess, not everything"
else
  bad "every request was refused -- the cap is rejecting traffic it should admit"
fi
if [ "$NOTHER" -eq 0 ]; then
  ok "no unexpected status codes"
else
  # Distinguish "the cap misbehaved" from "the backend refused the query".
  # Only the first is this feature's problem, and conflating them would make
  # the suite fail for reasons it is not testing.
  bad "$NOTHER request(s) returned neither 200 nor 429 -- if these are backend "\
"errors the probe query is too heavy; if not, the cap is returning the wrong code"
fi
echo

# --- 2. the refusal is counted --------------------------------------------
echo "[2] refusals are visible in metrics"
sleep 1
DEN_AFTER=$(metric grafana_datasource_ratelimit_concurrency_denied_total)
DELTA=$(( DEN_AFTER - DEN_BEFORE ))
note "denied_total ${DEN_BEFORE} -> ${DEN_AFTER}"
if [ "$DELTA" -ge "$N429" ] && [ "$N429" -gt 0 ]; then
  ok "counter rose by $DELTA, covering the $N429 refusals seen"
elif [ "$N429" -eq 0 ]; then
  note "skipped: nothing was refused"
else
  bad "counter rose by $DELTA but $N429 requests were refused -- refusals are not being counted"
fi
echo

# --- 3. the 429 says something useful --------------------------------------
# The whole point of the wording work: a concurrency refusal cannot be waited
# out, so it must not offer a wait, and it must not tell a service account to
# close browser tabs.
echo "[3] the 429 body is actionable"
TMP=$(mktemp -d)
for i in $(seq 1 "$N"); do
  ( curl -s -u "$AUTH" -D "$TMP/h$i" -o "$TMP/b$i" \
      -X POST "$GRAFANA/api/ds/query" -H 'Content-Type: application/json' \
      -d "{\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"$DS_UID\",\"type\":\"prometheus\"},\"expr\":\"sum(rate(container_cpu_usage_seconds_total[5m]))\",\"range\":true,\"instant\":false,\"intervalMs\":1000,\"maxDataPoints\":20000}],\"from\":\"$(( ($(date +%s)-86400) * 1000 ))\",\"to\":\"$(( $(date +%s) * 1000 ))\"}" \
      >/dev/null 2>&1 ) &
done
wait

BODY=""
for i in $(seq 1 "$N"); do
  if has "$(cat "$TMP/h$i" 2>/dev/null)" "429"; then
    BODY=$(cat "$TMP/b$i" 2>/dev/null)
    HDRS=$(cat "$TMP/h$i" 2>/dev/null)
    break
  fi
done

if [ -n "$BODY" ]; then
  note "body: $(printf '%s' "$BODY" | head -c 200)"
  MSG=$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("message",""))' 2>/dev/null)
  KIND=$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("kind",""))' 2>/dev/null)

  if [ -n "$MSG" ]; then
    ok "message present, which is what the UI renders"
  else
    bad "no message field -- the user would see a bare 429"
  fi
  if [ "$KIND" = "concurrent" ]; then
    ok "kind=concurrent tells a client waiting is not the remedy"
  else
    bad "kind=$KIND, want concurrent"
  fi
  if hasi "$HDRS" "^retry-after:"; then
    bad "Retry-After is present -- a slot frees when the caller's own request "\
"ends, which is not a duration this layer knows"
  else
    ok "no Retry-After, correctly"
  fi
  for w in panel tab dashboard browser; do
    if has "$(printf '%s' "$MSG" | tr 'A-Z' 'a-z')" "$w"; then
      bad "message mentions '$w', which means nothing to a service account"
    fi
  done
  ok "no browser-only advice in the message"
else
  bad "could not capture a 429 body to inspect"
fi
rm -rf "$TMP"
echo

# --- 4. slots come back ----------------------------------------------------
# A slot taken and never returned shrinks that identity's allowance for the
# life of the process, and it would show up here first.
echo "[4] the cap recovers once traffic stops"
sleep 3
HELD=$(metric grafana_datasource_ratelimit_concurrency_held)
if [ "${HELD:-0}" -eq 0 ]; then
  ok "concurrency_held back to 0"
else
  bad "concurrency_held = $HELD with nothing running -- slots are leaking"
fi

CODE=$(curl -s -u "$AUTH" -o /dev/null -w '%{http_code}' \
  -X POST "$GRAFANA/api/ds/query" -H 'Content-Type: application/json' \
  -d "{\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"$DS_UID\",\"type\":\"prometheus\"},\"expr\":\"up\",\"instant\":true}],\"from\":\"$(( ($(date +%s)-300) * 1000 ))\",\"to\":\"$(( $(date +%s) * 1000 ))\"}" 2>/dev/null)
if [ "$CODE" = "200" ]; then
  ok "a single request afterwards -> 200"
else
  bad "a single request afterwards -> $CODE; the identity is still blocked"
fi
echo

# --- 5. nothing slipped through uncounted ---------------------------------
echo "[5] no uncounted admissions during any of this"
FO=$(metric grafana_datasource_ratelimit_concurrency_fail_open_total)
if [ "${FO:-0}" -eq 0 ]; then
  ok "fail_open_total = 0"
else
  bad "fail_open_total = $FO -- the eviction protocol let requests past the cap"
fi
echo

echo "==============================================="
printf " %d passed, %d failed\n" "$PASS" "$FAIL"
echo "==============================================="
[ "$FAIL" -eq 0 ]
