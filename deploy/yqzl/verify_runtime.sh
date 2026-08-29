#!/usr/bin/env bash
set -euo pipefail

site_root=/www/wwwroot/tx.nstarzx.cn
psql=/www/server/pgsql/bin/psql
units=(
  gateway
  admin
  worker
  session-recovery
  outbox-dispatcher
  channel-dispatcher
  post-turn-projector
  wecom-connector
)

tenant_id="${TRPC_VERIFY_TENANT_ID:-}"
binding_id="${TRPC_VERIFY_BINDING_ID:-}"
if [[ -z "$tenant_id" || -z "$binding_id" ]]; then
  echo "TRPC_VERIFY_TENANT_ID and TRPC_VERIFY_BINDING_ID are required; refusing hard-coded tenant checks" >&2
  exit 1
fi
if [[ ! "$tenant_id" =~ ^[A-Za-z0-9._:-]+$ || ! "$binding_id" =~ ^[A-Za-z0-9._:-]+$ ]]; then
  echo "verification identifiers contain unsupported URL or SQL characters" >&2
  exit 1
fi

echo CONTROL_PLANE
export PGPASSWORD="$(<"$site_root/secrets/migration_database_password")"
control_output="$("$psql" -h 127.0.0.1 -U trpc_migration -d trpc_agent_service -At -v ON_ERROR_STOP=1 \
  -v tenant_id="$tenant_id" -v binding_id="$binding_id" <<'SQL'
SELECT concat(tenant_id, '|', status, '|v=', control_version)
  FROM tenants
 WHERE tenant_id = :'tenant_id';
SELECT concat(
         a.app_id,
         '|active=', a.active_config_version,
         '|provider=', c.config_json->'model'->>'provider'
       )
  FROM agent_apps AS a
  JOIN config_revisions AS c
    ON (c.tenant_id, c.app_id, c.version) =
       (a.tenant_id, a.app_id, a.active_config_version)
 WHERE a.tenant_id = :'tenant_id';
SELECT concat(
         binding_id,
         '|', channel,
         '|enabled=', enabled,
         '|secret_refs_ready=',
         CASE channel
           WHEN 'feishu' THEN secret_refs ? 'verification_token'
             AND secret_refs ? 'encrypt_key'
             AND secret_refs ? 'app_secret'
           WHEN 'wecom_ai_bot' THEN secret_refs ? 'bot_secret'
           ELSE false
         END
       )
  FROM channel_bindings
 WHERE tenant_id = :'tenant_id'
   AND binding_id = :'binding_id';
SQL
)"
printf '%s\n' "$control_output"
if [[ "$(printf '%s\n' "$control_output" | sed '/^[[:space:]]*$/d' | wc -l)" -lt 3 ]]; then
  echo "tenant/config/binding verification returned incomplete rows" >&2
  exit 1
fi
if ! printf '%s\n' "$control_output" | grep -Eq "^${binding_id//./\\.}\\|.*\\|enabled=t\\|secret_refs_ready=t$"; then
  echo "requested channel binding is disabled or its secret references are incomplete" >&2
  exit 1
fi
unset PGPASSWORD

echo SECRET_FILES
stat -c '%U:%G %a %s %n' \
  "$site_root/secrets/runtime_database_password" \
  "$site_root/secrets/migration_database_password" \
  "$site_root/secrets/redis_password" \
  "$site_root/secrets/session_hmac_key" \
  "$site_root/secrets/emergency_queue_key" \
  "$site_root/secrets/minio_root_password"

echo SERVICES
for unit in "${units[@]}"; do
  state="$(systemctl is-active "trpc-agent@$unit")"
  restarts="$(systemctl show "trpc-agent@$unit" -p NRestarts --value)"
  memory_max="$(systemctl show "trpc-agent@$unit" -p MemoryMax --value)"
  printf '%s|%s|restarts=%s|memory_max=%s\n' "$unit" "$state" "$restarts" "$memory_max"
  if [[ "$unit" == worker ]]; then
    if [[ "$memory_max" == infinity || ! "$memory_max" =~ ^[0-9]+$ || "$memory_max" -lt 2147483648 ]]; then
      echo "worker MemoryMax must be at least 2 GiB" >&2
      exit 1
    fi
  elif [[ "$memory_max" == infinity || ! "$memory_max" =~ ^[0-9]+$ ]]; then
    echo "$unit MemoryMax is not bounded" >&2
    exit 1
  fi
done

echo DEPENDENCIES
REDISCLI_AUTH="$(<"$site_root/secrets/redis_password")" redis-cli -p 6380 ping | grep -qx PONG
curl -fsS --max-time 5 http://127.0.0.1:9000/minio/health/ready >/dev/null
echo dependencies_ready=yes

echo RECENT_ERROR_LINES
for unit in "${units[@]}"; do
  count="$({
    journalctl -q -u "trpc-agent@$unit" -p err..alert \
      --since '30 minutes ago' --no-pager -o cat || true
  } | sed '/^[[:space:]]*$/d' | wc -l)"
  printf '%s|%s\n' "$unit" "$count"
done

echo LEAK_SCAN
umask 077
pattern_file="$(mktemp)"
journal_file="$(mktemp)"
trap 'rm -f "$pattern_file" "$journal_file"' EXIT
find "$site_root/secrets" -maxdepth 1 -type f -exec cat {} \; >"$pattern_file"
journalctl -q -u 'trpc-agent@*' --since '30 minutes ago' --no-pager -o cat \
  >"$journal_file"
if grep -Fq -f "$pattern_file" "$journal_file"; then
  echo journal_secret_leak=yes
  exit 1
else
  echo journal_secret_leak=no
fi
if find /www/wwwlogs -maxdepth 1 -type f -name 'tx.nstarzx.cn*.log' \
  -exec grep -Fq -f "$pattern_file" {} +; then
  echo nginx_secret_leak=yes
  exit 1
else
  echo nginx_secret_leak=no
fi

echo HTTPS
curl -fsS --max-time 10 https://tx.nstarzx.cn/health/ready
echo
invalid_signature_http="$(
  curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Content-Type: application/json' \
    --data '{}' \
    "https://tx.nstarzx.cn/v1/channels/feishu/$binding_id/callback"
)"
echo "invalid_signature_http=$invalid_signature_http"
if [[ "$invalid_signature_http" != 403 ]]; then
  exit 1
fi
