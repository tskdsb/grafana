#!/bin/bash
# BOE verification for the dsratelimit admin write path, on real MySQL.
#
# This script is intentionally strict: every setup/cleanup HTTP status, response
# body, concurrent writer status, and final field value is checked. A malformed
# or missing response must fail rather than be interpreted as a successful test.
#
# Usage: GRAFANA_URL=... GRAFANA_AUTH=user:pass ./boe_verify_rowlock.sh
set -uo pipefail

URL="${GRAFANA_URL:?set GRAFANA_URL}"
AUTH="${GRAFANA_AUTH:?set GRAFANA_AUTH}"
API="$URL/api/admin/datasource-rate-limits"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/dsratelimit-rowlock.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ok()  { printf '  PASS  %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }

put() {
  curl -sS -o /dev/null -w '%{http_code}\n' -u "$AUTH" -X PUT \
    -H 'Content-Type: application/json' -d "$2" "$API/$1"
}

del() {
  curl -sS -o /dev/null -w '%{http_code}\n' -u "$AUTH" -X DELETE "$API/$1"
}

fetch_rule() {
  local path=$1 out=$2 code
  code=$(curl -sS -o "$out" -w '%{http_code}' -u "$AUTH" "$API/$path") || return 1
  [ "$code" = "200" ] || return 1
  python3 - "$out" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    value = json.load(f)
rule = value.get("rule", value)
if not isinstance(rule, dict):
    raise SystemExit("response has no rule object")
PY
}

assert_fields() {
  local file=$1; shift
  python3 - "$file" "$@" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    value = json.load(f)
rule = value.get("rule", value)
for item in sys.argv[2:]:
    key, raw = item.split("=", 1)
    expected = None if raw == "null" else int(raw) if raw.lstrip("-").isdigit() else raw
    if key not in rule:
        raise SystemExit("missing field %s" % key)
    if rule[key] != expected:
        raise SystemExit("%s=%r, want %r" % (key, rule[key], expected))
PY
}

all_codes_are() {
  local expected=$1; shift
  local file code
  for file in "$@"; do
    [ -f "$file" ] || return 1
    IFS= read -r code <"$file" || return 1
    [[ "$code" =~ ^[0-9]{3}$ ]] || return 1
    [ "$code" = "$expected" ] || return 1
    [ "$(wc -l <"$file" | tr -d ' ')" = "1" ] || return 1
  done
}

codes_are_one_200_one_400() {
  local a b sorted
  IFS= read -r a <"$1" || return 1
  IFS= read -r b <"$2" || return 1
  [[ "$a" =~ ^[0-9]{3}$ && "$b" =~ ^[0-9]{3}$ ]] || return 1
  sorted=$(printf '%s\n%s\n' "$a" "$b" | sort | tr '\n' ' ')
  [ "$sorted" = "200 400 " ]
}

cleanup_rule() {
  [ "$(del "$1")" = "200" ]
}

if [ "${DSRATELIMIT_SELFTEST:-}" = "1" ]; then
  printf '200\n' >"$TMP/code200"
  printf '400\n' >"$TMP/code400"
  printf '500\n' >"$TMP/code500"
  printf '200500\n' >"$TMP/concatenated"
  printf '{"Rate":10,"Burst":100,"Concurrency":5}\n' >"$TMP/seed.json"
  printf '{"Rate":30,"Burst":100,"Concurrency":9}\n' >"$TMP/target.json"
  printf 'not json\n' >"$TMP/bad.json"

  # Reproduce the old assertions' false positives before checking the strict ones.
  old_t1_passes() { [ "$1" != "nil" ] && [ "$2" != "nil" ]; }
  old_t2_passes() {
    local r=$1 b=$2
    ! { [ "$r" != "nil" ] && [ "$b" != "nil" ] && [ "$b" -lt "$r" ] 2>/dev/null; }
  }
  old_t3_passes() { ! grep -q '^5' "$1"; }
  old_t1_passes 10 5 || exit 1
  old_t2_passes ERR ERR || exit 1
  old_t3_passes "$TMP/concatenated" || exit 1

  all_codes_are 200 "$TMP/code200" || exit 1
  ! all_codes_are 200 "$TMP/code500" || exit 1
  ! all_codes_are 200 "$TMP/concatenated" || exit 1
  codes_are_one_200_one_400 "$TMP/code200" "$TMP/code400" || exit 1
  ! codes_are_one_200_one_400 "$TMP/code200" "$TMP/code500" || exit 1
  assert_fields "$TMP/target.json" Rate=30 Burst=100 Concurrency=9 || exit 1
  ! assert_fields "$TMP/seed.json" Rate=30 Burst=100 Concurrency=9 2>/dev/null || exit 1
  ! assert_fields "$TMP/bad.json" Rate=30 2>/dev/null || exit 1
  echo "self-test passed: malformed statuses, 5xx, stale values and bad JSON are rejected"
  exit 0
fi

echo "=== T1  concurrent edits to different fields: both target values survive ==="
for round in 1 2 3; do
  cleanup_rule user/9101 || { bad "round $round: cleanup failed"; continue; }
  [ "$(put user/9101 '{"mode":"limited","rate":10,"burst":100,"concurrency":5}')" = "200" ] \
    || { bad "round $round: seed failed"; continue; }
  put user/9101 '{"mode":"limited","rate":30}' >"$TMP/t1a" & p1=$!
  put user/9101 '{"mode":"limited","concurrency":9}' >"$TMP/t1b" & p2=$!
  wait "$p1"; wait "$p2"
  if all_codes_are 200 "$TMP/t1a" "$TMP/t1b" \
    && fetch_rule user/9101 "$TMP/t1.json" \
    && assert_fields "$TMP/t1.json" Mode=limited Rate=30 Burst=100 Concurrency=9; then
    ok "round $round: both writes returned 200; final rate=30 burst=100 concurrency=9"
  else
    bad "round $round: writer status, JSON response, or exact final values were wrong"
  fi
done

echo
echo "=== T2  concurrent rate/burst edits: one accepted, one rejected, valid serial result ==="
for round in 1 2 3; do
  cleanup_rule user/9102 || { bad "round $round: cleanup failed"; continue; }
  [ "$(put user/9102 '{"mode":"limited","rate":10,"burst":100}')" = "200" ] \
    || { bad "round $round: seed failed"; continue; }
  put user/9102 '{"mode":"limited","rate":80}' >"$TMP/t2a" & p1=$!
  put user/9102 '{"mode":"limited","burst":20}' >"$TMP/t2b" & p2=$!
  wait "$p1"; wait "$p2"
  valid_final=false
  if fetch_rule user/9102 "$TMP/t2.json"; then
    assert_fields "$TMP/t2.json" Mode=limited Rate=80 Burst=100 && valid_final=true
    assert_fields "$TMP/t2.json" Mode=limited Rate=10 Burst=20 && valid_final=true
  fi
  if codes_are_one_200_one_400 "$TMP/t2a" "$TMP/t2b" && [ "$valid_final" = true ]; then
    ok "round $round: statuses were {200,400}; final pair matches an allowed serial result"
  else
    bad "round $round: expected statuses {200,400} and final 80/100 or 10/20"
  fi
done

echo
echo "=== T3  10 writers: every write succeeds and exact final values survive ==="
cleanup_rule user/9103 || bad "T3 cleanup failed"
if [ "$(put user/9103 '{"mode":"limited","rate":10,"burst":100,"concurrency":5}')" != "200" ]; then
  bad "T3 seed failed"
else
  files=()
  for i in $(seq 1 5); do
    files+=("$TMP/t3_r$i" "$TMP/t3_c$i")
    put user/9103 '{"mode":"limited","rate":20}' >"$TMP/t3_r$i" &
    put user/9103 '{"mode":"limited","concurrency":7}' >"$TMP/t3_c$i" &
  done
  wait
  if all_codes_are 200 "${files[@]}" \
    && fetch_rule user/9103 "$TMP/t3.json" \
    && assert_fields "$TMP/t3.json" Mode=limited Rate=20 Burst=100 Concurrency=7; then
    ok "all 10 writes returned 200; final rate=20 burst=100 concurrency=7"
  else
    bad "a status was malformed/non-200, GET was invalid, or exact final values were wrong"
  fi
fi

echo
echo "=== T4  partial-update three-state semantics ==="
cleanup_rule user/9104 || bad "T4 cleanup failed"
if [ "$(put user/9104 '{"mode":"limited","rate":10,"burst":100,"concurrency":5}')" = "200" ] \
  && [ "$(put user/9104 '{"mode":"limited","rate":30}')" = "200" ] \
  && fetch_rule user/9104 "$TMP/t4a.json" \
  && assert_fields "$TMP/t4a.json" Mode=limited Rate=30 Burst=100 Concurrency=5; then
  ok "omitted fields retained"
else
  bad "setup/update/GET failed or omitted fields changed"
fi
if [ "$(put user/9104 '{"mode":"limited","concurrency":null}')" = "200" ] \
  && fetch_rule user/9104 "$TMP/t4b.json" \
  && assert_fields "$TMP/t4b.json" Mode=limited Rate=30 Burst=100 Concurrency=null; then
  ok "explicit null cleared only concurrency"
else
  bad "null update/GET failed or cleared the wrong field"
fi

echo
echo "=== T5  outright invalid pair is rejected and remains absent ==="
cleanup_rule user/9105 || bad "T5 cleanup failed"
code=$(put user/9105 '{"mode":"limited","rate":100,"burst":2}')
if [ "$code" = "400" ]; then
  get_code=$(curl -sS -o "$TMP/t5.json" -w '%{http_code}' -u "$AUTH" "$API/user/9105")
  if [ "$get_code" = "404" ]; then
    ok "rate=100 burst=2 returned 400 and no rule was persisted"
  else
    bad "invalid PUT returned 400 but subsequent GET got $get_code, expected 404"
  fi
else
  bad "rate=100 burst=2 got $code, expected 400"
fi

echo
echo "=== cleanup ==="
for t in 9101 9102 9103 9104 9105; do
  cleanup_rule "user/$t" || bad "cleanup user/$t failed"
done

echo
echo "================ $pass passed, $fail failed ================"
[ "$fail" -eq 0 ]
