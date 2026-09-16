#!/bin/bash
# End-to-end test for the datasource query rate limiter, against a running
# Grafana. Unit tests cover the logic; this covers what they cannot -- real
# routing, real middleware ordering, real auth, real datasource plugins, real
# DB persistence, real reload, and the actual metrics a human will read.
#
#   GRAFANA=https://host/grafana ADMIN=admin:pw bash e2e-dsratelimit.sh
#
# Every case prints PASS or FAIL with the observed value, and the script exits
# non-zero if any failed. Nothing is asserted from code inspection: each case
# sends requests and reads what comes back.
#
# The script leaves no rules behind -- it deletes the ones it creates on the
# way out, including after a failure.

set -uo pipefail

GRAFANA="${GRAFANA:-https://ml-maas.bytedance.net/cn-beijing-boe/grafana}"
ADMIN="${ADMIN:-admin:prom-operator}"
API="$GRAFANA/api"
ADM="$API/admin/datasource-rate-limits"

# Datasources under test. PROM is the one whose quota this feature exists for;
# the others are here because the charging path must not depend on the plugin,
# and that claim is only worth something if a non-Prometheus datasource is
# actually exercised.
PROM_UID="${PROM_UID:-b6699235-9888-4161-80bc-ec9e0024579f}"   # Prometheus-flex
MYSQL_UID="${MYSQL_UID:-dd4_MBMSk}"                            # Mysql
TLS_UID="${TLS_UID:-f13297b3-4f37-43ef-ba7b-69f415f396d8}"     # LogService (tls)
CM_UID="${CM_UID:-PB67B041CA1C50139}"                          # cloud-monitor
ES_UID="${ES_UID:-w6Nck0cIk}"                                  # elasticsearch

PASS=0; FAIL=0; SKIP=0
declare -a FAILED_NAMES=()

c() { curl -sk -u "$ADMIN" --max-time 30 "$@"; }

ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m  %-46s %s\n' "$1" "${2:-}"; }
no()   { FAIL=$((FAIL+1)); FAILED_NAMES+=("$1"); printf '  \033[31mFAIL\033[0m  %-46s %s\n' "$1" "${2:-}"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33mSKIP\033[0m  %-46s %s\n' "$1" "${2:-}"; }
sec()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# eq NAME EXPECTED ACTUAL
eq() { if [ "$2" = "$3" ]; then ok "$1" "= $3"; else no "$1" "期望 $2，实到 $3"; fi; }

# HTTP status of a ds/query for one datasource, with N queries in the body.
q_status() {
  local uid="$1" n="${2:-1}" qs="" i
  for ((i=0;i<n;i++)); do
    [ -n "$qs" ] && qs="$qs,"
    qs="$qs{\"refId\":\"Q$i\",\"datasource\":{\"uid\":\"$uid\"},\"expr\":\"up\",\"intervalMs\":60000,\"maxDataPoints\":10}"
  done
  c -o /dev/null -w '%{http_code}' -X POST "$API/ds/query" \
    -H 'Content-Type: application/json' \
    -d "{\"from\":\"now-5m\",\"to\":\"now\",\"queries\":[$qs]}"
}

# Same, but against a path variant (used for the trailing-slash case).
q_status_path() {
  local path="$1" uid="$2" n="${3:-1}" qs="" i
  for ((i=0;i<n;i++)); do
    [ -n "$qs" ] && qs="$qs,"
    qs="$qs{\"refId\":\"Q$i\",\"datasource\":{\"uid\":\"$uid\"},\"expr\":\"up\"}"
  done
  c -o /dev/null -w '%{http_code}' -X POST "$GRAFANA$path" \
    -H 'Content-Type: application/json' \
    -d "{\"from\":\"now-5m\",\"to\":\"now\",\"queries\":[$qs]}"
}

put_rule()  { c -o /dev/null -w '%{http_code}' -X PUT "$ADM/$1/$2" -H 'Content-Type: application/json' -d "$3"; }
del_rule()  { c -o /dev/null -w '%{http_code}' -X DELETE "$ADM/$1/$2"; }
stats()     { c "$ADM/stats"; }

# 等规则真正生效，而不是猜时间。
#
# Run() 的 reload tick 是 30 秒（ratelimit.go:256），而这个脚本原来一律 sleep 12
# ——比一个 tick 还短。之前几轮全绿是运气：只要前面的等待恰好跨过 tick 边界，
# 后面这条就能看到规则。实跑真的踩到了：tls 那条读出"扣了 0"，前后几条却 PASS，
# 差别只在时序。产品是对的（同一 UID 隔离重测 6 轮，每轮精确扣 3）。
#
# 轮询到 stats 里出现这个数据源为止，最多等 45 秒（1.5 个 tick）。
wait_ds_rule() {
  local uid="$1" i
  for i in $(seq 1 45); do
    [ "$(stats | jqf "print('$uid' in d['datasources'])")" = "True" ] && return 0
    sleep 1
  done
  return 1
}

# 身份规则不出现在 stats 的 datasources 里，只能等一个完整 tick + 余量。
wait_reload() { sleep 32; }

jqf() { python3 -c "import json,sys
try: d=json.load(sys.stdin)
except Exception: print('PARSE_ERR'); sys.exit()
$1" 2>/dev/null || echo "PARSE_ERR"; }

# Tokens left in a datasource bucket, per the admin stats endpoint.
ds_tokens() { stats | jqf "print(round(d['datasources'].get('$1',{}).get('tokens',-1),1))"; }
ds_source() { stats | jqf "print(d['datasources'].get('$1',{}).get('source','ABSENT'))"; }

# /metrics 抓一次存起来。不要用 `c ... | grep -q`: grep -q 命中即退出，
# curl 拿到 SIGPIPE 返回 23，在 pipefail 下整条管道判失败 —— 指标明明存在
# 却报"未出现"。首轮实跑就是这么误报了 10 条。
METRICS_CACHE=""
fetch_metrics() { METRICS_CACHE=$(c "$GRAFANA/metrics"); }
# grep -c 而非 grep -q: -q 命中即退出并关闭管道，上游 echo 拿到 SIGPIPE
# 返回 141，pipefail 下整条管道判失败 —— 指标存在却报"未出现"。首轮实跑
# 因此误报 10 条，改用 fetch_metrics 缓存后仍然误报，因为根因是 -q 本身。
has_metric() { [ "$(echo "$METRICS_CACHE" | grep -cE "^grafana_datasource_ratelimit_$1")" -gt 0 ]; }
metric_val() {
  echo "$METRICS_CACHE" | awk -v p="grafana_datasource_ratelimit_$1" \
    'index($0,p)==1 {s+=$NF} END {printf "%.0f", s+0}'
}
# 某数据源在某结果下累计扣了多少 token。计费必须看这个单调计数器，不能看
# stats 里的剩余 token: 桶以 rate/s 回满，rate=350 时一次 HTTP 往返就补回
# 上百，扣减根本观测不到。首轮实跑 5 条 query 读出"扣了 0"就是这个原因。
ds_tok_total() {
  echo "$METRICS_CACHE" | awk -v u="$1" -v o="${2:-allowed}" \
    '$0 ~ "datasource_tokens_total.*datasource=\""u"\".*outcome=\""o"\"" {print $NF; f=1} END {if(!f) print 0}'
}

cleanup() {
  printf '\n\033[1m== 清理\033[0m\n'
  for kv in "datasource $PROM_UID" "datasource $MYSQL_UID" "datasource $TLS_UID" \
            "datasource $CM_UID" "datasource $ES_UID" "user 1" "anon anon" \
            "default default" "enforcement default"; do
    set -- $kv
    code=$(del_rule "$1" "$2")
    [ "$code" = "200" ] && echo "  已删 $1/$2"
  done
}
trap cleanup EXIT

echo "目标: $GRAFANA"
echo "时间: $(date '+%F %T')"

# ---------------------------------------------------------------- 0. 前置
sec "0. 前置：部署的是不是这个分支"
V=$(c "$API/health" | jqf "print(d['version'],d['commit'][:11])")
echo "  版本: $V"
CODE=$(c -o /dev/null -w '%{http_code}' "$ADM/stats")
if [ "$CODE" != "200" ]; then
  no "限流功能已部署" "GET $ADM/stats -> ${CODE}（旧镜像？未部署？）"
  echo; echo "后面全部无法进行，先确认镜像已生效。"; exit 1
fi
ok "限流功能已部署" "stats -> 200"

S=$(stats)
ENABLED=$(echo "$S"  | jqf "print(d['enabled'])")
SHADOW=$(echo "$S"   | jqf "print(d['shadow_mode'])")
echo "  enabled=$ENABLED  shadow_mode=$SHADOW"
fetch_metrics
ENFORCING=$(metric_val enforcing)
if [ "$SHADOW" = "True" ]; then
  eq "影子模式下 enforcing 指标为 0" "0" "$ENFORCING"
else
  eq "真实拦截下 enforcing 指标为 1" "1" "$ENFORCING"
fi

# 影子模式下没有任何 429，拦截类断言无从谈起；用一条 datasource 规则验证。
ENFORCE=1
if [ "$SHADOW" = "True" ]; then
  ENFORCE=0
  echo
  echo "  注意：当前是影子模式，不会返回 429。"
  echo "  拦截类用例将标为 SKIP。要跑完整套，把 shadow_mode 设为 false 后重跑。"
fi

# ---------------------------------------------------------------- 1. admin API
sec "1. Admin API：参数校验"
eq "PUT datasource limited"          "200" "$(put_rule datasource "$PROM_UID" '{"mode":"limited","rate":350,"burst":420}')"
eq "PUT user blocked"                "200" "$(put_rule user 1 '{"mode":"blocked"}')"
eq "PUT anon limited"                "200" "$(put_rule anon anon '{"mode":"limited","rate":5,"burst":10}')"
eq "PUT user 非数字 target 应拒"      "400" "$(put_rule user john.doe '{"mode":"blocked"}')"
eq "PUT datasource blocked 应拒"      "400" "$(put_rule datasource "$PROM_UID" '{"mode":"blocked"}')"
eq "PUT lane 已废弃应拒"              "400" "$(put_rule lane default '{"mode":"limited","rate":10,"burst":20}')"
eq "PUT burst<rate 应拒"              "400" "$(put_rule datasource "$PROM_UID" '{"mode":"limited","rate":500,"burst":100}')"
eq "PUT rate=0 应拒"                  "400" "$(put_rule datasource "$PROM_UID" '{"mode":"limited","rate":0,"burst":0}')"
eq "PUT 负数应拒"                     "400" "$(put_rule datasource "$PROM_UID" '{"mode":"limited","rate":-5,"burst":-5}')"
eq "PUT 未知 kind 应拒"               "400" "$(put_rule org 1 '{"mode":"limited","rate":10,"burst":20}')"
eq "PUT 未知 mode 应拒"               "400" "$(put_rule user 2 '{"mode":"bogus"}')"
eq "GET 列表"                        "200" "$(c -o /dev/null -w '%{http_code}' "$ADM")"
eq "GET 单条"                        "200" "$(c -o /dev/null -w '%{http_code}' "$ADM/datasource/$PROM_UID")"
eq "DELETE user/1"                   "200" "$(del_rule user 1)"

# 免重启改基线与拦截开关。这两个 kind 是唯一不经由 byKey 解析的，走的是
# rulesSnapshot 上的独立字段，所以单测通过不代表接口这一层接对了 —— 这里验的是
# 真的能写进去、stats 真的报出来、删掉真的回落。
sec "1c. Admin API：免重启调整基线与拦截开关"
eq "PUT default 基线"                "200" "$(put_rule default default '{"mode":"limited","rate":33,"burst":44}')"
eq "PUT default 非法 target 应拒"    "400" "$(put_rule default 1 '{"mode":"limited","rate":10,"burst":20}')"
eq "PUT default blocked 应拒"        "400" "$(put_rule default default '{"mode":"blocked"}')"
eq "PUT enforcement 开"              "200" "$(put_rule enforcement default '{"mode":"limited"}')"
eq "PUT enforcement 关"              "200" "$(put_rule enforcement default '{"mode":"unlimited"}')"
eq "PUT enforcement 带 rate 应拒"    "400" "$(put_rule enforcement default '{"mode":"limited","rate":10,"burst":20}')"
eq "PUT enforcement blocked 应拒"    "400" "$(put_rule enforcement default '{"mode":"blocked"}')"

# 等一个 reload tick，再看 stats 是否报出 db 来源和新数值。
sleep 45
DEF_RATE=$(stats | jqf "print(d.get('defaults',{}).get('rate',-1))")
DEF_SRC=$(stats | jqf "print(d.get('defaults',{}).get('source','?'))")
eq "stats 报出新基线"                "33" "$DEF_RATE"
eq "stats 标记来源为 db"             "db" "$DEF_SRC"
SHADOW_SRC=$(stats | jqf "print(d.get('sources',{}).get('shadow_mode','?'))")
eq "stats 标记拦截开关来自 db"       "db" "$SHADOW_SRC"

eq "DELETE default"                  "200" "$(del_rule default default)"
eq "DELETE enforcement"              "200" "$(del_rule enforcement default)"
sleep 45
DEF_SRC2=$(stats | jqf "print(d.get('defaults',{}).get('source','?'))")
eq "删除后基线回落到 ini"            "ini" "$DEF_SRC2"
SHADOW_SRC2=$(stats | jqf "print(d.get('sources',{}).get('shadow_mode','?'))")
eq "删除后拦截开关回落到 ini"        "ini" "$SHADOW_SRC2"

sec "1b. Admin API：鉴权"
NOAUTH=$(curl -sk --max-time 20 -o /dev/null -w '%{http_code}' "$ADM/stats")
if [ "$NOAUTH" = "401" ] || [ "$NOAUTH" = "302" ] || [ "$NOAUTH" = "403" ]; then
  ok "未认证访问被拒" "-> $NOAUTH"
else
  no "未认证访问被拒" "期望 401/403/302，实到 $NOAUTH"
fi

# ---------------------------------------------------------------- 2. 生效与持久化
sec "2. 规则生效与来源"
wait_ds_rule "$PROM_UID" || echo "  (警告: 规则 45 秒未生效)"
eq "stats 报出 db 来源"  "db"  "$(ds_source "$PROM_UID")"
T=$(ds_tokens "$PROM_UID")
if python3 -c "import sys; sys.exit(0 if abs(float('$T')-420)<1 else 1)" 2>/dev/null; then
  ok "剩余 token 为满桶" "= $T"
else
  no "剩余 token 为满桶" "期望约 420，实到 $T"
fi

# ---------------------------------------------------------------- 3. 计费
sec "3. 计费：按后端请求数而非请求数"
fetch_metrics; BEFORE=$(ds_tok_total "$PROM_UID")
q_status "$PROM_UID" 5 >/dev/null
fetch_metrics; AFTER=$(ds_tok_total "$PROM_UID")
DELTA=$((AFTER - BEFORE))
eq "一个请求 5 条 query 扣 5 token" "5" "$DELTA"

sec "3b. 尾斜杠不能绕过计费"
# 尾斜杠曾经能绕过计费: web/tree.go 匹配前剥尾斜杠，请求照常执行，而计费的
# 路径判断没剥，于是只按 1 计。发 3 条 query，扣 3 才算没绕过，扣 1 就是绕过。
fetch_metrics; B=$(ds_tok_total "$PROM_UID")
q_status_path "/api/ds/query/" "$PROM_UID" 3 >/dev/null
fetch_metrics; A2=$(ds_tok_total "$PROM_UID")
D2=$((A2 - B))
if [ "$D2" -eq 3 ]; then
  ok "/api/ds/query/ 照常计费" "扣了 3"
elif [ "$D2" -eq 1 ]; then
  no "/api/ds/query/ 照常计费" "只扣 1（尾斜杠绕过了计费！）"
else
  no "/api/ds/query/ 照常计费" "扣了 $D2，期望 3"
fi

# ---------------------------------------------------------------- 4. 其他类型数据源
sec "4. 非 Prometheus 数据源同样计费"
for pair in "mysql $MYSQL_UID" "tls $TLS_UID" "cloudmonitor $CM_UID" "elasticsearch $ES_UID"; do
  set -- $pair
  name="$1"; uid="$2"
  code=$(put_rule datasource "$uid" '{"mode":"limited","rate":100,"burst":120}')
  if [ "$code" != "200" ]; then skip "$name 配额可配置" "PUT -> $code"; continue; fi
  wait_ds_rule "$uid" || { no "$name 配额生效" "45 秒内未出现在 stats"; continue; }
  fetch_metrics; b=$(ds_tok_total "$uid")
  q_status "$uid" 3 >/dev/null
  fetch_metrics; a=$(ds_tok_total "$uid")
  eq "$name 计入配额（3 条 query）" "3" "$((a - b))"
done

sec "4b. 未配额的数据源不受数据源层限制"
UNQ="${UNQ_UID:-e062d5fa-fe30-4072-9787-a84e44ffd555}"   # boe-test, 未配
S1=$(stats | jqf "print('$UNQ' in d['datasources'])")
eq "未配额数据源不出现在 stats" "False" "$S1"
CODE=$(q_status "$UNQ" 1)
if [ "$CODE" != "429" ]; then ok "未配额数据源可查询" "-> $CODE"; else no "未配额数据源可查询" "-> 429"; fi

# ---------------------------------------------------------------- 5. 拦截
sec "5. 真实拦截（需 shadow_mode=false）"
if [ "$ENFORCE" = "0" ]; then
  skip "数据源配额打满后返回 429"     "影子模式"
  skip "429 带 Retry-After"          "影子模式"
  skip "身份桶打满后返回 429"         "影子模式"
  skip "blocked 身份被拒"            "影子模式"
  skip "配额耗尽不影响其他数据源"     "影子模式"
  skip "429 正文说明是哪个限额"      "影子模式"
  skip "429 正文点名数据源"          "影子模式"
  skip "X-RateLimit-Scope 头"        "影子模式"
  skip "文案不含裸 UID"              "影子模式"
  skip "429 正文不泄露身份"          "影子模式"
  skip "blocked 不承诺重试"          "影子模式"
else
  put_rule datasource "$PROM_UID" '{"mode":"limited","rate":2,"burst":3}' >/dev/null
  wait_ds_rule "$PROM_UID" || no "拦截前置：配额生效" "45 秒未生效"
  GOT429=0; RA=""; BODY=""; SCOPEHDR=""
  for i in $(seq 1 12); do
    resp=$(c -D - -X POST "$API/ds/query" -H 'Content-Type: application/json' \
      -d "{\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"$PROM_UID\"},\"expr\":\"up\"}]}" \
      -w '\nSTATUS:%{http_code}')
    if echo "$resp" | grep -c 'STATUS:429' >/dev/null 2>&1 && [ "$(echo "$resp" | grep -c 'STATUS:429')" -gt 0 ]; then
      GOT429=1
      RA=$(echo "$resp" | grep -i '^retry-after:' | tr -d '\r' | awk '{print $2}')
      SCOPEHDR=$(echo "$resp" | grep -i '^x-ratelimit-scope:' | tr -d '\r' | awk '{print $2}')
      BODY=$(echo "$resp" | sed -n 's/.*\({"[^\n]*\)/\1/p' | tail -1)
      break
    fi
  done
  if [ "$GOT429" = "1" ]; then ok "数据源配额打满后返回 429" "第 $i 次"; else no "数据源配额打满后返回 429" "12 次都没拒"; fi
  if [ -n "$RA" ] && [ "$RA" -ge 1 ] 2>/dev/null; then ok "429 带 Retry-After" "= $RA"; else no "429 带 Retry-After" "头缺失或非法: '$RA'"; fi

  # 用户看到的那句话。前端直接渲染 message，所以它必须自己说清是哪个限额、
  # 额度多少、下一步做什么 —— 只测状态码等于不测这个功能对人的那一半。
  if [ "$(echo "$BODY" | grep -c 'rate limit reached')" -gt 0 ]; then
    ok "429 正文说明是哪个限额" "$(echo "$BODY" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | cut -c1-70)"
  else
    no "429 正文说明是哪个限额" "正文: $(echo "$BODY" | cut -c1-120)"
  fi
  # 数据源超限时必须点名数据源，而不是报调用者自己的额度
  if [ "$(echo "$BODY" | grep -c "\"datasource\":\"$PROM_UID\"")" -gt 0 ] \
     && [ "$(echo "$BODY" | grep -c '"scope":"datasource"')" -gt 0 ]; then
    ok "429 正文点名数据源" "scope=datasource"
  else
    no "429 正文点名数据源" "正文: $(echo "$BODY" | cut -c1-160)"
  fi
  # 文案里出现 36 位 UID 只有噪音价值（真机上实测过）；它应该只在机器可读字段里
  MSG=$(echo "$BODY" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p')
  if [ "$(echo "$MSG" | grep -c "$PROM_UID")" -eq 0 ]; then
    ok "文案不含裸 UID" "只在 datasource 字段里"
  else
    no "文案不含裸 UID" "文案: $MSG"
  fi

  # lane 这个概念已经删了，头和字段都不该再出现
  if [ "$SCOPEHDR" = "datasource" ]; then
    ok "X-RateLimit-Scope 头" "= $SCOPEHDR"
  else
    no "X-RateLimit-Scope 头" "得到 '$SCOPEHDR'"
  fi
  if [ "$(echo "$BODY" | grep -c '"lane"')" -eq 0 ]; then
    ok "429 正文不泄露身份" "无 lane 字段"
  else
    no "429 正文不泄露身份" "仍有已废弃的 lane 字段"
  fi

  # 配额耗尽时，别的数据源不该被连累
  OTHER=$(q_status "$UNQ" 1)
  if [ "$OTHER" != "429" ]; then ok "配额耗尽不影响其他数据源" "-> $OTHER"; else no "配额耗尽不影响其他数据源" "-> 429"; fi

  put_rule datasource "$PROM_UID" '{"mode":"limited","rate":350,"burst":420}' >/dev/null

  # 身份桶：admin 自己限死
  put_rule user 1 '{"mode":"blocked"}' >/dev/null
  wait_reload
  BRESP=$(c -X POST "$API/ds/query" -H 'Content-Type: application/json' \
    -d "{\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"$UNQ\"},\"expr\":\"up\"}]}" \
    -w '\nSTATUS:%{http_code}')
  BCODE=$(echo "$BRESP" | sed -n 's/^STATUS:\(.*\)/\1/p')
  eq "blocked 身份被拒" "429" "$BCODE"
  # blocked 永不放行，说"稍后再试"会让客户端进入永不终止的重试循环
  if [ "$(echo "$BRESP" | grep -c 'not allowed')" -gt 0 ] \
     && [ "$(echo "$BRESP" | grep -c 'try again')" -eq 0 ]; then
    ok "blocked 不承诺重试" "指向管理员"
  else
    no "blocked 不承诺重试" "正文: $(echo "$BRESP" | tail -1 | cut -c1-140)"
  fi
  del_rule user 1 >/dev/null
  wait_reload
fi

# ---------------------------------------------------------------- 6. 影子模式语义
sec "6. 影子模式语义"
if [ "$ENFORCE" = "1" ]; then
  skip "影子模式下不拒绝但仍计数" "当前非影子模式"
else
  put_rule datasource "$PROM_UID" '{"mode":"limited","rate":1,"burst":1}' >/dev/null
  wait_ds_rule "$PROM_UID" || no "影子前置：配额生效" "45 秒未生效"
  ALL200=1
  for i in $(seq 1 8); do
    [ "$(q_status "$PROM_UID" 1)" = "429" ] && ALL200=0
  done
  [ "$ALL200" = "1" ] && ok "影子模式下配额=1 仍全部放行" "8/8" || no "影子模式下配额=1 仍全部放行" "出现了 429"
  fetch_metrics; D=$(metric_val 'denied_total')
  if [ "${D:-0}" -gt 0 ]; then ok "影子模式仍记录 denied" "denied_total=$D"; else no "影子模式仍记录 denied" "denied_total=0（应有投影）"; fi
  put_rule datasource "$PROM_UID" '{"mode":"limited","rate":350,"burst":420}' >/dev/null
fi

# ---------------------------------------------------------------- 7. 可观测
sec "7. 指标与日志"
fetch_metrics
for m in attempted_total allowed_total denied_total datasource_tokens_total queries_per_request \
         user_rate enforcing active_keys last_successful_reload_timestamp_seconds fail_open_total \
         invalid_rule_total oversized_body_total; do
  if has_metric "$m"; then ok "指标存在 $m"; else no "指标存在 $m" "未在 /metrics 中出现"; fi
done

# user_rate 是给标定 default_user_rate 用的，光"存在"不够——采样 goroutine 必须
# 真的在跑。这个断言只有等过一个 10s 窗口才有意义，前面的 wait_ds_rule 已经等够了。
URC=$(echo "$METRICS_CACHE" | awk '/^grafana_datasource_ratelimit_user_rate_count/ {print $NF}' | head -1)
if [ "${URC:-0}" -gt 0 ] 2>/dev/null; then
  ok "user_rate 已采到样本" "count=$URC"
else
  no "user_rate 已采到样本" "count=${URC:-无}，采样 goroutine 可能没跑"
fi
for m in fail_open_total invalid_rule_total oversized_body_total; do
  v=$(metric_val "$m"); eq "$m 应为 0" "0" "${v:-NA}"
done
RELOAD=$(metric_val last_successful_reload_timestamp_seconds)
NOW=$(date +%s)
AGE=$((NOW - ${RELOAD%.*}))
if [ "$AGE" -lt 120 ] 2>/dev/null; then ok "reload 时间戳是新鲜的" "${AGE}s 前"; else no "reload 时间戳是新鲜的" "${AGE}s 前（reload 挂了？）"; fi

# ---------------------------------------------------------------- 8. 回退与安全阀
sec "8. 删除规则后回落"
del_rule datasource "$PROM_UID" >/dev/null
wait_reload
SRC=$(ds_source "$PROM_UID")
if [ "$SRC" = "ABSENT" ] || [ "$SRC" = "ini" ]; then
  ok "删除 db 行后回落" "source=$SRC"
else
  no "删除 db 行后回落" "仍为 $SRC"
fi

sec "9. 正常功能未受影响"
eq "首页可访问"      "200" "$(c -o /dev/null -w '%{http_code}' "$GRAFANA/")"
eq "数据源列表"      "200" "$(c -o /dev/null -w '%{http_code}' "$API/datasources")"
eq "搜索 dashboard"  "200" "$(c -o /dev/null -w '%{http_code}' "$API/search?limit=1")"
eq "告警规则接口"    "200" "$(c -o /dev/null -w '%{http_code}' "$API/v1/provisioning/alert-rules")"
eq "用户接口"        "200" "$(c -o /dev/null -w '%{http_code}' "$API/users?perpage=1")"

sec "10. 畸形输入不致崩"
for body in '{}' '{"queries":[]}' '{"queries":null}' '{"queries":[{"datasource":null}]}' 'not json' ''; do
  code=$(c -o /dev/null -w '%{http_code}' -X POST "$API/ds/query" -H 'Content-Type: application/json' -d "$body")
  if [ "$code" = "500" ] || [ "$code" = "502" ] || [ "$code" = "000" ]; then
    no "畸形 body 不 5xx: ${body:0:22}" "-> $code"
  else
    ok "畸形 body 不 5xx: ${body:0:22}" "-> $code"
  fi
done
eq "畸形后服务仍健康" "200" "$(c -o /dev/null -w '%{http_code}' "$API/health")"

# ---------------------------------------------------------------- 汇总
printf '\n\033[1m======== 汇总 ========\033[0m\n'
printf '  PASS %d    FAIL %d    SKIP %d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
  printf '\n  失败项:\n'
  for n in "${FAILED_NAMES[@]}"; do printf '    - %s\n' "$n"; done
  exit 1
fi
echo "  全部通过"
