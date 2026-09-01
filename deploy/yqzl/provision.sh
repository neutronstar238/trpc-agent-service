#!/usr/bin/env bash
set -euo pipefail

readonly SITE_ROOT=/www/wwwroot/tx.nstarzx.cn
readonly APP_ROOT="$SITE_ROOT/app"
readonly SERVICE_USER=trpcagent
readonly SERVICE_GROUP=trpcagent
readonly PG_BIN=/www/server/pgsql/bin
readonly PG_CONFIG="$PG_BIN/pg_config"
readonly DATABASE_NAME=trpc_agent_service
readonly METRICS_ROLE=trpc_metrics
readonly METRICS_SECRET_NAME=trpc-metrics-secrets
readonly METRICS_SECRET_KEY=TRPC_SERVICE_METRICS_DATABASE_DSN
readonly MINIO_BUCKET=trpc-artifacts
readonly MINIO_IMAGE=quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z
readonly MINIO_MC_IMAGE=quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z
declare -a secret_temp_paths=()

cleanup_sensitive_values() {
  local path
  unset redis_password metrics_password metrics_password_uri metrics_database_dsn
  for path in "${secret_temp_paths[@]}"; do
    case "$path" in
      "$SITE_ROOT"/secrets/.secret.*|"$SITE_ROOT"/secrets/.minio-env.*|\
      "$SITE_ROOT"/secrets/.metrics-dsn.*)
        rm -f -- "$path"
        ;;
    esac
  done
}
trap cleanup_sensitive_values EXIT

if [[ ${EUID} -ne 0 ]]; then
  echo "provision.sh must run as root" >&2
  exit 1
fi

if [[ ! -x "$PG_BIN/psql" || ! -x "$PG_CONFIG" ]]; then
  echo "the expected BaoTa PostgreSQL installation was not found" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required for the yqzl MinIO service" >&2
  exit 1
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$SITE_ROOT" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
if [[ ! -x "$APP_ROOT/.venv/bin/trpc-service" ]]; then
  echo "the active release virtual environment is missing trpc-service" >&2
  exit 1
fi
# Release preparation runs as root and may inherit a restrictive umask.  Keep
# the virtual environment immutable to the service account while ensuring the
# service group can traverse directories and execute the installed entrypoint.
chown -R root:"$SERVICE_GROUP" "$APP_ROOT/.venv"
chmod -R g+rX,o-rwx "$APP_ROOT/.venv"

install -d -m 0755 -o root -g root "$SITE_ROOT"
install -d -m 0755 -o www -g www "$SITE_ROOT/.well-known" "$SITE_ROOT/.well-known/acme-challenge"
install -d -m 0750 -o root -g "$SERVICE_GROUP" "$SITE_ROOT/config" "$SITE_ROOT/secrets"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$SITE_ROOT/data" "$SITE_ROOT/logs"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$SITE_ROOT/data/redis"
# The pinned MinIO image runs as UID/GID 1000.  Keep its bind-mounted data
# writable only by that unprivileged container identity.
install -d -m 0750 -o 1000 -g 1000 "$SITE_ROOT/data/minio"

runtime_env_source="${TRPC_YQZL_RUNTIME_ENV_SOURCE:-$APP_ROOT/deploy/yqzl/runtime.env}"
if [[ ! -f "$runtime_env_source" ]]; then
  echo "a real deploy/yqzl/runtime.env is required; refusing to copy the example" >&2
  exit 1
fi
if grep -Eq '(^|[[:space:]])TRPC_SERVICE_ENVIRONMENT=development([[:space:]]|$)|(^|[[:space:]])TRPC_SERVICE_ALLOW_DEVELOPMENT_TOKEN=true([[:space:]]|$)' "$runtime_env_source"; then
  echo "refusing to provision a development runtime configuration" >&2
  exit 1
fi
if [[ "$runtime_env_source" == *.example ]]; then
  echo "refusing to provision an example runtime configuration" >&2
  exit 1
fi
if grep -Eiq '(replace-with|change-me|replace_with|example\.internal|localhost)' "$runtime_env_source"; then
  echo "runtime.env still contains a placeholder value" >&2
  exit 1
fi

make_secret() {
  local path=$1
  local kind=$2
  local temporary
  if [[ -s "$path" ]]; then
    return
  fi
  temporary=$(mktemp "$SITE_ROOT/secrets/.secret.XXXXXX")
  secret_temp_paths+=("$temporary")
  chmod 0600 "$temporary"
  case "$kind" in
    password) openssl rand -base64 36 | tr -d '\r\n' >"$temporary" ;;
    session) openssl rand -base64 48 | tr -d '\r\n' >"$temporary" ;;
    exact32) openssl rand -base64 32 | tr -d '\r\n' >"$temporary" ;;
    minio_user)
      printf 'trpcminio_%s' "$(openssl rand -hex 12)" >"$temporary"
      ;;
    feishu_binding)
      printf 'feishu-%s' "$(openssl rand -hex 12)" >"$temporary"
      ;;
    wecom_binding)
      printf 'wecom-%s' "$(openssl rand -hex 12)" >"$temporary"
      ;;
    *) echo "unknown secret kind: $kind" >&2; exit 1 ;;
  esac
  chown root:"$SERVICE_GROUP" "$temporary"
  chmod 0640 "$temporary"
  mv "$temporary" "$path"
}

make_secret "$SITE_ROOT/secrets/redis_password" password
make_secret "$SITE_ROOT/secrets/session_hmac_key" session
make_secret "$SITE_ROOT/secrets/emergency_queue_key" exact32
make_secret "$SITE_ROOT/secrets/development_token" password
make_secret "$SITE_ROOT/secrets/minio_root_user" minio_user
make_secret "$SITE_ROOT/secrets/minio_root_password" password
make_secret "$SITE_ROOT/config/feishu_binding_id" feishu_binding
make_secret "$SITE_ROOT/config/wecom_binding_id" wecom_binding
chown root:"$SERVICE_GROUP" "$SITE_ROOT/secrets/minio_root_user" \
  "$SITE_ROOT/secrets/minio_root_password"
chmod 0640 "$SITE_ROOT/secrets/minio_root_user" "$SITE_ROOT/secrets/minio_root_password"

write_s3_access_environment() {
  local path="$SITE_ROOT/secrets/minio-s3-access.env"
  local temporary
  temporary=$(mktemp "$SITE_ROOT/secrets/.minio-env.XXXXXX")
  secret_temp_paths+=("$temporary")
  chmod 0600 "$temporary"
  printf 'TRPC_SERVICE_S3_ACCESS_KEY=%s\n' "$(<"$SITE_ROOT/secrets/minio_root_user")" >"$temporary"
  chown root:"$SERVICE_GROUP" "$temporary"
  chmod 0640 "$temporary"
  mv "$temporary" "$path"
}

write_s3_access_environment

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl libssl-dev python3.12-venv redis-server
systemctl disable --now redis-server.service >/dev/null 2>&1 || true

install_pg_extension() {
  local extension=$1
  local present
  present=$(runuser -u postgres -- "$PG_BIN/psql" -Atc \
    "SELECT 1 FROM pg_available_extensions WHERE name='$extension'" || true)
  [[ "$present" == "1" ]]
}

if ! install_pg_extension pgcrypto \
  || ! ldd "$($PG_CONFIG --pkglibdir)/pgcrypto.so" 2>/dev/null | grep -q 'libcrypto'; then
  pg_work=$(mktemp -d /tmp/trpc-pgcrypto.XXXXXX)
  curl -fsSL -o "$pg_work/postgresql.tar.bz2" \
    https://mirrors.aliyun.com/postgresql/source/v18.0/postgresql-18.0.tar.bz2
  printf '%s  %s\n' \
    '0d5b903b1e5fe361bca7aa9507519933773eb34266b1357c4e7780fdee6d6078' \
    "$pg_work/postgresql.tar.bz2" | sha256sum --check --status
  tar -xjf "$pg_work/postgresql.tar.bz2" -C "$pg_work"
  make -C "$pg_work/postgresql-18.0/contrib/pgcrypto" USE_PGXS=1 \
    PG_CONFIG="$PG_CONFIG" with_llvm=no SHLIB_LINK='-lcrypto -lz'
  make -C "$pg_work/postgresql-18.0/contrib/pgcrypto" USE_PGXS=1 \
    PG_CONFIG="$PG_CONFIG" with_llvm=no SHLIB_LINK='-lcrypto -lz' install
  case "$pg_work" in /tmp/trpc-pgcrypto.*) rm -rf -- "$pg_work" ;; esac
fi

if ! install_pg_extension vector; then
  vector_work=$(mktemp -d /tmp/trpc-pgvector.XXXXXX)
  curl -fsSL -o "$vector_work/pgvector.tar.gz" \
    https://codeload.github.com/pgvector/pgvector/tar.gz/refs/tags/v0.8.1
  tar -xzf "$vector_work/pgvector.tar.gz" -C "$vector_work"
  make -C "$vector_work/pgvector-0.8.1" PG_CONFIG="$PG_CONFIG" with_llvm=no
  make -C "$vector_work/pgvector-0.8.1" PG_CONFIG="$PG_CONFIG" with_llvm=no install
  case "$vector_work" in /tmp/trpc-pgvector.*) rm -rf -- "$vector_work" ;; esac
fi

install -m 0640 -o root -g "$SERVICE_GROUP" "$runtime_env_source" "$SITE_ROOT/config/runtime.env"
install -m 0640 -o root -g "$SERVICE_GROUP" "$APP_ROOT/deploy/yqzl/gateway.env" "$SITE_ROOT/config/gateway.env"
install -m 0640 -o root -g "$SERVICE_GROUP" "$APP_ROOT/deploy/yqzl/admin.env" "$SITE_ROOT/config/admin.env"

bash "$APP_ROOT/deploy/yqzl/bootstrap_database_roles.sh"

_url_encode_uri_component() {
  local value=$1
  local encoded=""
  local character
  local index
  local byte

  LC_ALL=C
  for ((index = 0; index < ${#value}; index++)); do
    character=${value:index:1}
    case "$character" in
      [a-zA-Z0-9.~_-]) encoded+="$character" ;;
      *)
        printf -v byte '%%%02X' "'${character}"
        encoded+="$byte"
        ;;
    esac
  done
  printf '%s' "$encoded"
}

publish_metrics_kubernetes_secret() {
  # Bare-metal installs leave the namespace unset.  ACK deployments opt in by
  # supplying it, so ordinary yqzl provisioning never depends on kubectl.
  local namespace="${TRPC_YQZL_KUBERNETES_NAMESPACE:-}"
  local metrics_database_host="${TRPC_YQZL_METRICS_DATABASE_HOST:-127.0.0.1}"
  local metrics_database_port="${TRPC_YQZL_METRICS_DATABASE_PORT:-5432}"
  local metrics_password_uri
  local temporary
  local -a kubectl_args=()

  [[ -z "$namespace" ]] && return 0
  command -v kubectl >/dev/null 2>&1 || {
    echo "kubectl is required when TRPC_YQZL_KUBERNETES_NAMESPACE is set" >&2
    return 1
  }
  [[ "$metrics_database_host" != *[[:space:]/@]* ]] || {
    echo "TRPC_YQZL_METRICS_DATABASE_HOST is invalid" >&2
    return 1
  }
  [[ "$metrics_database_port" =~ ^[0-9]+$ ]] || {
    echo "TRPC_YQZL_METRICS_DATABASE_PORT is invalid" >&2
    return 1
  }

  metrics_password=$(<"$SITE_ROOT/secrets/metrics_database_password")
  metrics_password_uri=$(_url_encode_uri_component "$metrics_password")
  metrics_database_dsn="postgresql://${METRICS_ROLE}:${metrics_password_uri}@${metrics_database_host}:${metrics_database_port}/${DATABASE_NAME}"
  temporary=$(mktemp "$SITE_ROOT/secrets/.metrics-dsn.XXXXXX")
  secret_temp_paths+=("$temporary")
  chmod 0600 "$temporary"
  printf '%s' "$metrics_database_dsn" >"$temporary"
  if [[ -n "${TRPC_YQZL_KUBECONFIG:-}" ]]; then
    kubectl_args+=(--kubeconfig "$TRPC_YQZL_KUBECONFIG")
  fi
  if [[ -n "${TRPC_YQZL_KUBE_CONTEXT:-}" ]]; then
    kubectl_args+=(--context "$TRPC_YQZL_KUBE_CONTEXT")
  fi
  kubectl "${kubectl_args[@]}" create secret generic "$METRICS_SECRET_NAME" \
    --namespace "$namespace" \
    --from-file="$METRICS_SECRET_KEY=$temporary" \
    --dry-run=client -o yaml |
    kubectl "${kubectl_args[@]}" apply --server-side \
      --field-manager=trpc-yqzl-provision --namespace "$namespace" -f - >/dev/null
}

publish_metrics_kubernetes_secret

redis_password=$(<"$SITE_ROOT/secrets/redis_password")
printf 'user default on >%s ~* &* +@all\n' "$redis_password" >"$SITE_ROOT/secrets/redis.acl"
chown root:"$SERVICE_GROUP" "$SITE_ROOT/secrets/redis.acl"
chmod 0640 "$SITE_ROOT/secrets/redis.acl"

install -m 0640 -o root -g "$SERVICE_GROUP" "$APP_ROOT/deploy/yqzl/redis.conf" "$SITE_ROOT/config/redis.conf"
install -m 0644 "$APP_ROOT/deploy/yqzl/trpc-agent-redis.service" /etc/systemd/system/trpc-agent-redis.service
install -m 0644 "$APP_ROOT/deploy/yqzl/trpc-agent@.service" /etc/systemd/system/trpc-agent@.service
install -m 0644 "$APP_ROOT/deploy/yqzl/trpc-agent-wecom-standby.service" \
  /etc/systemd/system/trpc-agent-wecom-standby.service
install -d -m 0755 /etc/systemd/system/trpc-agent@wecom-connector.service.d
install -m 0644 "$APP_ROOT/deploy/yqzl/trpc-agent-wecom-primary.conf" \
  /etc/systemd/system/trpc-agent@wecom-connector.service.d/10-app-pythonpath.conf
install -m 0644 "$APP_ROOT/deploy/yqzl/trpc-agent-minio.service" /etc/systemd/system/trpc-agent-minio.service
install -d -m 0755 /etc/systemd/system/trpc-agent@worker.service.d
printf '%s\n' '[Service]' 'MemoryHigh=1536M' 'MemoryMax=2G' \
  > /etc/systemd/system/trpc-agent@worker.service.d/resources.conf
systemctl daemon-reload
systemctl enable docker.service >/dev/null 2>&1 || true
systemctl start docker.service
docker pull "$MINIO_IMAGE" >/dev/null
docker pull "$MINIO_MC_IMAGE" >/dev/null
systemctl enable --now trpc-agent-redis.service
systemctl enable trpc-agent-minio.service
systemctl start trpc-agent-minio.service

REDISCLI_AUTH=$(<"$SITE_ROOT/secrets/redis_password") redis-cli -p 6380 ping | grep -qx PONG

docker run --rm --user 0:0 --network host --read-only --cap-drop=ALL \
  --security-opt no-new-privileges \
  --env MC_CONFIG_DIR=/tmp/.mc \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount "type=bind,src=$SITE_ROOT/secrets/minio_root_user,dst=/run/secrets/minio_root_user,readonly" \
  --mount "type=bind,src=$SITE_ROOT/secrets/minio_root_password,dst=/run/secrets/minio_root_password,readonly" \
  --entrypoint /bin/sh "$MINIO_MC_IMAGE" -ceu \
  'mc alias set local http://127.0.0.1:9000 "$(cat /run/secrets/minio_root_user)" "$(cat /run/secrets/minio_root_password)" >/dev/null
   mc mb --ignore-existing "local/$1"
   mc anonymous set none "local/$1" >/dev/null' sh "$MINIO_BUCKET"

echo "provisioning complete"
