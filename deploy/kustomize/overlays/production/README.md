# Production overlay

The overlay intentionally references a pre-created Secret named
`trpc-service-secrets` and a separate `trpc-worker-secrets`; no credential is
stored in this repository. Populate them from an ExternalSecret/Vault/KMS
integration (or create them out-of-band) with
the environment-variable keys consumed by the deployments, including at
least:

- `TRPC_SERVICE_DATABASE_DSN`
- `TRPC_SERVICE_REDIS_URL`
- `TRPC_SERVICE_S3_ACCESS_KEY`
- `TRPC_SERVICE_S3_SECRET_KEY` (the ConfigMap points
  `TRPC_SERVICE_S3_SECRET_KEY_REF` at `env://TRPC_SERVICE_S3_SECRET_KEY`)
- `TRPC_SERVICE_OIDC_ISSUER`
- `TRPC_SERVICE_OIDC_AUDIENCE`

For a private image registry, include one additional Secret of type
`kubernetes.io/dockerconfigjson` in the same external Secret manifest. Keep
its `metadata.namespace` unset so the acceptance gate can bind it to its
disposable namespace, and set the non-sensitive
`TRPC_K8S_RUNTIME_IMAGE_PULL_SECRET` value to that Secret's name. The gate
validates only kind/name/namespace/type metadata before any server-side
dry-run, injects the reference into the migration Job and all Deployments,
and passes the same name to the bounded HPA load Job. Registry credentials are
never copied into the evidence report.

For a direct Kustomize deployment outside the runtime gate, copy
`image-pull-secret-patch.example.yaml` into the environment-specific overlay,
replace the placeholder with the same Secret name, and target both
`Deployment` and `Job` resources from that overlay's `kustomization.yaml`.
The example patch is deliberately not enabled by default, so public-registry
deployments do not contain a hard-coded pull Secret name.

The worker Secret must also provide `TRPC_SERVICE_WORKER_DATABASE_DSN`,
`TRPC_SERVICE_WORKER_DATABASE_DSN_REF`,
`TRPC_SERVICE_WORKER_DATABASE_PASSWORD`, and
`TRPC_SERVICE_WORKER_DATABASE_PASSWORD_REF`. Only worker, dispatcher,
projector, connector, and recovery pods mount this Secret. The dedicated
`trpc_worker` role is expected to be a non-superuser with explicit EXECUTE
grants on the cross-tenant SECURITY DEFINER functions; the normal tenant
runtime role must not receive that Secret.

The backlog exporter uses a third Secret named `trpc-metrics-secrets` with
only `TRPC_SERVICE_METRICS_DATABASE_DSN`.  It must connect as the dedicated
`trpc_metrics` login created before migration `0016`; that login is
`NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS` and can execute
only `public.count_session_ready_backlog()`.  Do not reuse the worker DSN.

The ConfigMap also sets an explicit tenant-secret policy: file references are
confined to `/run/secrets`, the environment allowlist is empty by default, and
`TRPC_SERVICE_MODEL_ENDPOINT_HOSTS` must be replaced with the reviewed model
provider hosts used by this deployment.  Feishu stale binding-cache fallback
is disabled.  Emergency queue keys are versioned with
`TRPC_SERVICE_EMERGENCY_QUEUE_KEY_VERSION`; populate
`TRPC_SERVICE_EMERGENCY_QUEUE_PREVIOUS_KEY_REFS` only while each referenced
previous key is present in the Secret and being retired.

Replace the example image name/digest and the managed service endpoints in
`../../base/config.yaml` (or add an environment-specific patch) before
applying. The runtime account is expected to be a non-owner PostgreSQL role;
database migrations run separately with the `migrate` role. The production
runtime gate rejects tag-only images, `example.*` endpoints, and placeholder
digests.

The worker capacity envelope is explicit: the production overlay sets
`TRPC_SERVICE_WORKER_CONCURRENCY=10` and the HPA allows 20 worker replicas,
which is a maximum 200 concurrent-turn envelope. A Prometheus Adapter (or
KEDA implementation) must expose `trpc_session_ready_backlog`; CPU-only HPA
evidence is insufficient and keeps the runtime gate `not_run`.  The supplied
exporter derives this value from runnable PostgreSQL `session_mailboxes`;
Redis stream length is not authoritative because its wake-up entries are
reconstructable.

The base NetworkPolicy intentionally does not grant arbitrary `0.0.0.0/0:443`
egress. Add a reviewed production overlay policy for the exact private
endpoints/provider CIDRs required by the deployment; otherwise outbound model
and IM calls remain fail-closed.

Render and inspect the manifests before applying:

```bash
kubectl kustomize deploy/kustomize/overlays/production
kubectl apply --server-side -k deploy/kustomize/overlays/production
```

## Scheduler version changes

The production ConfigMap is pinned to scheduler `v2` and the matching
`trpc:session-ready:v2` / `trpc-session-ready-v2` transport. A change between
`v1` and `v2` is a protocol cutover, not a normal Deployment rollout. Do not
edit `TRPC_SERVICE_SCHEDULER_VERSION`, the Redis stream, or the consumer group
while old and new pods overlap, and do not use a normal `RollingUpdate` for the
version transition. Pause the Gateway/WeCom ingress, drain the old PostgreSQL
outbox and Redis group, stop the old Worker/Outbox processes, apply the reviewed
version-specific ConfigMap while scheduler-related replicas are zero, then
start recovery/dispatcher/worker and restore ingress in that order.

Only a same-version image/configuration change may use the Deployment
`RollingUpdate` strategy. Keep both versioned Redis streams, groups, emergency
groups, and outbox rows during the observation window; never delete or trim them
to make a drain check pass. The complete SQL/Redis drain criteria and the
v2→v1 rollback guard (all v2 mailboxes must be `IDLE` with
`accepted_sequence = resolved_sequence`) are in
[`docs/scheduler-cutover.md`](../../../../docs/scheduler-cutover.md).
