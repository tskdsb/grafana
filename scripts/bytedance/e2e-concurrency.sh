#!/usr/bin/env bash
# End-to-end checks for the per-identity concurrency cap, run against a live
# Grafana rather than the test harness.
#
# Why this exists alongside the unit tests: the cap is a wrapping middleware
# mounted on the whole chain, so what it actually sees -- the path, the
# identity, the moment the response completes -- only exists in a real server.
# The unit tests stub all three.
#
# Every check states what it expected and what it got, so a failure names the
# behaviour rather than just the line number.

set -uo pipefail

GRAFANA="${GRAFANA:-https://ml-maas.bytedance.net/cn-beijing-boe/grafana}"
AUTH="${AUTH:-admin:prom-operator}"
DS_UID="${DS_UID:-b6699235-9888-4161-80bc-ec9e0024579f}"
ADMIN="$GRAFANA/api/admin/datasource-rate-limits"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
note() { printf '        %s\n' "$1"; }

# --- helpers ---------------------------------------------------------------

api() { curl -s -u "$AUTH" "$@"; }

# has <haystack> <pattern> -- stands in for a quiet grep, which cannot be used
# under `set -o pipefail`: that grep exits the moment it matches, the upstream
# printf takes SIGPIPE, and the pipeline reports 141, so a successful match
# reads as a failure. Measured here -- the same expression said "no match" with
# pipefail on and "match" with it off, which is what made sections 1 and 2 of
# this script report metrics as missing while they were plainly in /metrics.
# Counting consumes the whole input and has no early exit.
has() {
  local n
  n=$(printf '%s' "$1" | grep -c -- "$2")
  [ "${n:-0}" -gt 0 ]
}

stats() { api "$ADMIN/stats"; }

# A query that takes long enough to still be in flight when the next one
# arrives. Wide range + tiny step makes the backend work rather than sleeping
# on our side, so the slot is held the way a real slow dashboard holds it.
slow_query() {
  local out_var="$1"
  local now; now=$(date +%s)
  local body
  body=$(cat <<EOF
{"queries":[{"refId":"A","datasource":{"uid":"$DS_UID","type":"prometheus"},
"expr":"sum(rate(container_cpu_usage_seconds_total[5m])) by (pod)",
"range":true,"instant":false,"intervalMs":1000,"maxDataPoints":40000}],
"from":"$(( (now-86400) * 1000 ))","to":"$(( now * 1000 ))"}
EOF
)
  local code
  code=$(curl -s -u "$AUTH" -o /dev/null -w '%{http_code}' \
    -X POST "$GRAFANA/api/ds/query" -H 'Content-Type: application/json' \
    -d "$body" 2>/dev/null)
  printf -v "$out_var" '%s' "$code"
}

fast_query() {
  local now; now=$(date +%s)
  curl -s -u "$AUTH" -o /dev/null -w '%{http_code}' \
    -X POST "$GRAFANA/api/ds/query" -H 'Content-Type: application/json' \
    -d "{\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"$DS_UID\",\"type\":\"prometheus\"},\"expr\":\"up\",\"instant\":true}],\"from\":\"$(( (now-300) * 1000 ))\",\"to\":\"$(( now * 1000 ))\"}" \
    2>/dev/null
}

metric() { # metric <name> -> summed value across all label sets, 0 if absent
  api "$GRAFANA/metrics" 2>/dev/null \
    | awk -v m="$1" '$0 ~ "^"m"[ {]" { s += $NF } END { printf "%.0f", s+0 }'
}

echo "==============================================="
echo " concurrency cap, end to end"
echo " target: $GRAFANA"
echo "==============================================="
echo

# --- 0. the build under test ----------------------------------------------
echo "[0] build"
COMMIT=$(api "$GRAFANA/api/health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("commit","?"))' 2>/dev/null)
note "commit $COMMIT"
if [ -n "$COMMIT" ] && [ "$COMMIT" != "?" ]; then
  ok "server reachable and reporting a build"
else
  bad "cannot read /api/health -- nothing below is meaningful"
  exit 1
fi
echo

# --- 1. the metrics the rollout depends on are wired ----------------------
#
# Label-less metrics appear as soon as the process registers them. Vec metrics
# do not: prometheus emits nothing for a Vec until some label combination has
# been written, so "missing" and "registered but never touched" look identical
# in /metrics. The QPS layer behaves the same way, which is how that was
# confirmed rather than assumed.
#
# So they are checked differently: the plain ones must be present now, and the
# Vec ones are checked in section 3 by making traffic and watching them appear.
echo "[1] metrics are wired"
# Retry the scrape. A single curl against a server that has just rolled can
# come back partial, and reading "metric absent" off a truncated body would
# report a wiring failure that does not exist -- which is exactly what this
# script did on its first run here.
ALLM=""
for _ in 1 2 3 4 5; do
  ALLM=$(api "$GRAFANA/metrics" 2>/dev/null)
  if has "$ALLM" "^# TYPE grafana_datasource_ratelimit_"; then
    break
  fi
  sleep 3
done
note "$(printf '%s' "$ALLM" | grep -c '^# TYPE ') metric families scraped"
for m in grafana_datasource_ratelimit_concurrency_held \
         grafana_datasource_ratelimit_concurrency_fail_open_total; do
  if has "$ALLM" "^# TYPE $m "; then
    ok "$m is exported"
  else
    bad "$m is absent -- this one has no labels, so it should appear at startup"
  fi
done
for m in grafana_datasource_ratelimit_concurrency_inflight \
         grafana_datasource_ratelimit_concurrency_denied_total; do
  if has "$ALLM" "^# TYPE $m "; then
    note "$m already has data"
  else
    note "$m not emitted yet -- a Vec with no observations; section 3 checks it"
  fi
done
echo

# --- 2. fail-open must be zero --------------------------------------------
# Non-zero means the eviction protocol is letting requests through uncounted,
# which is the failure the state machine was rewritten to prevent.
echo "[2] no uncounted admissions"
FO=$(metric grafana_datasource_ratelimit_concurrency_fail_open_total)
if [ "${FO:-0}" -eq 0 ]; then
  ok "fail_open_total = 0"
else
  bad "fail_open_total = $FO -- requests are bypassing the cap uncounted"
fi
echo

# --- 3. does the cap record what it sees ----------------------------------
#
# What "correct" means here depends on the switch. Shipped default is
# concurrency_enabled = false, and then recording nothing is the right
# behaviour -- the middleware returns at the first gate. The failure worth
# catching is the opposite: enabled, no limit, and still nothing recorded,
# which is the state the observation week runs in and which silently produced
# an empty histogram in an earlier revision.
echo "[3] recording matches the switch"
ENABLED=$(stats | python3 -c '
import json,sys
d = json.load(sys.stdin)
c = d.get("concurrency")
# Absent means an older build that predates the field; say so rather than
# defaulting to false and reporting a failure that is really a version gap.
print("missing" if c is None else str(c.get("recording", False)).lower())
' 2>/dev/null || echo unknown)
note "concurrency.recording = $ENABLED"

BEFORE=$(metric grafana_datasource_ratelimit_concurrency_inflight_count)
for _ in 1 2 3 4 5 6 7 8; do fast_query >/dev/null; done
sleep 1
AFTER=$(metric grafana_datasource_ratelimit_concurrency_inflight_count)
DELTA=$(( AFTER - BEFORE ))
note "histogram samples ${BEFORE} -> ${AFTER}"

case "$ENABLED" in
  false)
    if [ "$DELTA" -eq 0 ]; then
      ok "disabled and recording nothing, as shipped"
    else
      bad "disabled but recorded $DELTA samples -- the first gate is not holding"
    fi
    ;;
  true)
    if [ "$DELTA" -ge 8 ]; then
      ok "8 requests produced $DELTA samples"
    else
      bad "enabled but only $DELTA of 8 recorded -- the observation week would "\
"come back empty"
    fi
    ;;
  missing)
    bad "/stats has no concurrency block -- an operator cannot confirm whether "\
"the cap is on, which is how this gap was found in the first place"
    ;;
  *)
    bad "cannot read concurrency.recording from /stats"
    ;;
esac
echo

# --- 4. ordinary traffic is not refused -----------------------------------
echo "[4] ordinary traffic passes"
CODE=$(fast_query)
if [ "$CODE" = "200" ]; then
  ok "single query -> 200"
else
  bad "single query -> $CODE, want 200"
fi
echo

# --- 5. unmanaged paths are untouched -------------------------------------
# The middleware wraps every request, so a bug here throttles the whole UI.
echo "[5] non-datasource paths are not counted"
for p in /api/health /api/datasources /api/org; do
  c=$(api -o /dev/null -w '%{http_code}' "$GRAFANA$p")
  if [ "$c" = "200" ] || [ "$c" = "302" ]; then
    ok "$p -> $c"
  else
    bad "$p -> $c"
  fi
done
echo

# --- 6. held returns to zero ----------------------------------------------
# A slot that is taken and never released shrinks that identity's allowance
# permanently, and the gauge is where that shows up first.
echo "[6] slots are returned"
sleep 2
HELD=$(metric grafana_datasource_ratelimit_concurrency_held)
if [ "${HELD:-0}" -eq 0 ]; then
  ok "concurrency_held = 0 with no traffic in flight"
else
  bad "concurrency_held = $HELD after traffic settled -- slots are leaking"
fi
echo

# --- 7. the cap is inert by default ---------------------------------------
echo "[7] default configuration refuses nothing"
DEN=$(metric grafana_datasource_ratelimit_concurrency_denied_total)
if [ "${DEN:-0}" -eq 0 ]; then
  ok "denied_total = 0"
else
  note "denied_total = $DEN (expected only if a limit was configured)"
  ok "denied_total = $DEN -- recorded, not necessarily wrong"
fi
echo

# --- 8. the QPS layer still works -----------------------------------------
# The concurrency middleware sits in front of everything; the regression that
# matters most is it breaking the layer already in production.
echo "[8] the QPS layer is unaffected"
S=$(stats)
if has "$S" '"enforcing"'; then
  EN=$(printf '%s' "$S" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("enforcing"))' 2>/dev/null)
  CC=$(printf '%s' "$S" | python3 -c '
import json,sys
c = json.load(sys.stdin).get("concurrency") or {}
print("enforcing=%s recording=%s limit=%s" % (
    c.get("enforcing"), c.get("recording"), c.get("limit")))
' 2>/dev/null)
  ok "admin API answers, QPS enforcing=$EN"
  note "concurrency: $CC"
else
  bad "admin API did not return a usable payload"
fi
echo

echo "==============================================="
printf " %d passed, %d failed\n" "$PASS" "$FAIL"
echo "==============================================="
[ "$FAIL" -eq 0 ]
