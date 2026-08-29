"""Unit contract for the Agent Cell intent/effect boundary."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from trpc_service.cell.effects import (
    AmbiguousEffectOutcome,
    ConfirmationRequired,
    EffectClaim,
    EffectExecutionError,
    EffectKeyConflict,
    EffectLeaseConflict,
    EffectReceipt,
    EffectStatus,
    ExactlyOnceEffectExecutor,
    InMemoryEffectLedger,
    KnownEffectFailure,
    UnknownEffectOutcome,
    replace_intent_decision,
)
from trpc_service.cell.intents import (
    ConfirmationScope,
    IntentRisk,
    PolicyDecision,
    ToolIntent,
    arguments_hash,
    stable_effect_key,
)


def make_intent(**overrides: object) -> ToolIntent:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "cell_id": "cell-a",
        "session_id": "session-a",
        "intent_id": "intent-a",
        "tool_name": "create_ticket",
        "arguments": {"priority": "normal", "subject": "hello"},
        "risk": IntentRisk.LOW,
        "principal_id": "principal-a",
        "trace_id": "trace-a",
    }
    values.update(overrides)
    return ToolIntent(**values)  # type: ignore[arg-type]


def test_effect_key_is_order_independent_and_tenant_scoped() -> None:
    first = make_intent(arguments={"a": 1, "nested": {"z": 2, "a": 3}})
    second = make_intent(arguments={"nested": {"a": 3, "z": 2}, "a": 1})
    assert first.arguments_hash == second.arguments_hash
    assert first.effect_key == second.effect_key
    assert stable_effect_key(first) == first.effect_key
    assert make_intent(tenant_id="tenant-b").effect_key != first.effect_key
    assert arguments_hash({"a": 1}) == arguments_hash({"a": 1})
    assert make_intent(branch_id="candidate").effect_key != first.effect_key
    candidate = make_intent(arguments=first.arguments, branch_id="candidate")
    assert (
        stable_effect_key(
            tenant_id="tenant-a",
            cell_id="cell-a",
            session_id="session-a",
            intent_id="intent-a",
            tool_name="create_ticket",
            arguments=first.arguments,
            branch_id="candidate",
            principal_id="principal-a",
        )
        == candidate.effect_key
    )


def test_policy_and_risk_aliases_parse_to_canonical_values() -> None:
    intent = make_intent(policy_decision="needs-confirmation", risk="non-idempotent")
    assert intent.policy_decision is PolicyDecision.REQUIRE_CONFIRMATION
    assert intent.decision is PolicyDecision.REQUIRE_CONFIRMATION
    assert intent.risk is IntentRisk.NON_IDEMPOTENT
    assert intent.requires_confirmation


def test_invalid_policy_risk_and_argument_values_fail_closed() -> None:
    with pytest.raises(ValueError, match="unsupported policy decision"):
        PolicyDecision.parse("not-a-decision")
    with pytest.raises(ValueError, match="unsupported intent risk"):
        IntentRisk.parse("not-a-risk")
    with pytest.raises(TypeError, match="unsupported value"):
        arguments_hash({"unhashable": object()})
    with pytest.raises(ValueError, match="branch_id"):
        make_intent(branch_id="")
    with pytest.raises(TypeError, match="arguments"):
        make_intent(arguments=["not", "a", "mapping"])
    with pytest.raises(ValueError, match="intent_id"):
        make_intent(intent_id=123)


def test_canonical_arguments_cover_sequences_sets_and_hmac_keys() -> None:
    assert arguments_hash({"values": (1, 2)}) == arguments_hash({"values": [1, 2]})
    assert arguments_hash({"values": {"a", "b"}}) == arguments_hash({"values": {"b", "a"}})
    intent = make_intent(arguments={"values": [1, 2]})
    expanded = stable_effect_key(
        intent.tenant_id,
        intent.cell_id,
        intent.session_id,
        intent.intent_id,
        intent.tool_name,
        intent.arguments,
        branch_id=intent.branch_id,
        principal_id=intent.principal_id,
        capsule_digest=intent.capsule_digest,
    )
    assert expanded == intent.effect_key
    assert stable_effect_key(intent, key=b"k" * 32) != intent.effect_key
    assert stable_effect_key(intent, namespace="test-effect").startswith("test-effect:")
    with pytest.raises(ValueError, match="effect key fields"):
        stable_effect_key(tenant_id="tenant-a")
    with pytest.raises(ValueError, match="branch_id"):
        stable_effect_key(
            tenant_id="tenant-a",
            cell_id="cell-a",
            session_id="session-a",
            intent_id="intent-a",
            tool_name="tool",
            arguments={},
            branch_id="",
        )


def test_confirmation_scope_factories_and_optional_expiry() -> None:
    intent = make_intent(branch_id="candidate", risk=IntentRisk.CRITICAL)
    scope = ConfirmationScope.from_intent(intent, approved_by="operator")
    assert scope.branch_id == "candidate"
    assert scope.matches(intent)
    assert not scope.is_expired()
    with pytest.raises(ValueError, match="TTL"):
        intent.confirmation_scope(ttl_seconds=0)
    never_expires = replace(scope, expires_at=None)
    assert not never_expires.is_expired()
    assert not scope.matches(intent, now=datetime.now(UTC) + timedelta(hours=1))
    naive_scope = replace(scope, expires_at=datetime.now() + timedelta(minutes=1))
    assert naive_scope.matches(intent)
    assert not naive_scope.is_expired(now=datetime.now(UTC))
    for field_name in (
        "cell_id",
        "principal_id",
        "tool_name",
        "arguments_hash",
        "effect_key",
        "branch_id",
    ):
        altered = cast(Any, replace)(scope, **{field_name: "different"})
        assert not altered.matches(intent)


def test_missing_intent_id_is_deterministic_and_risk_classes_are_explicit() -> None:
    first = make_intent(intent_id="", request_id="request-1", branch_id="candidate")
    second = make_intent(intent_id="", request_id="request-1", branch_id="candidate")
    assert first.intent_id == second.intent_id
    assert first.args_hash == first.arguments_hash
    assert first.high_risk is False
    assert make_intent(risk=IntentRisk.MEDIUM).requires_confirmation is False
    for risk in (
        IntentRisk.HIGH,
        IntentRisk.CRITICAL,
        IntentRisk.NON_IDEMPOTENT,
        IntentRisk.UNKNOWN,
    ):
        assert make_intent(risk=risk).high_risk


def test_confirmation_scope_cannot_cross_identity_or_arguments() -> None:
    intent = make_intent(risk=IntentRisk.HIGH)
    scope = intent.confirmation_scope(approved_by="operator", approval_id="approval-1")
    assert scope.matches(intent)
    assert not scope.matches(make_intent(session_id="other-session"))
    assert not scope.matches(make_intent(arguments={"priority": "urgent"}))
    assert not scope.matches(make_intent(tenant_id="tenant-b"))
    expired = ConfirmationScope(
        tenant_id=intent.tenant_id,
        cell_id=intent.cell_id,
        session_id=intent.session_id,
        principal_id=intent.principal_id or "",
        tool_name=intent.tool_name,
        arguments_hash=intent.arguments_hash,
        effect_key=intent.effect_key,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    assert expired.is_expired()
    assert not expired.matches(intent)


@pytest.mark.asyncio
async def test_allow_is_exactly_once_and_cached_result_is_authoritative() -> None:
    ledger = InMemoryEffectLedger()
    executor = ExactlyOnceEffectExecutor(ledger)
    intent = make_intent()
    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def effect() -> dict[str, str]:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return {"ticket_id": "T-1"}

    first_task = asyncio.create_task(executor.execute(intent, effect))
    await started.wait()
    second_task = asyncio.create_task(executor.execute(intent, effect))
    await asyncio.sleep(0)
    release.set()
    first, second = await asyncio.gather(first_task, second_task)
    assert calls == 1
    assert first.status is EffectStatus.SUCCEEDED
    assert second.status is EffectStatus.SUCCEEDED
    assert first.result == second.result == {"ticket_id": "T-1"}
    again = await executor.execute(intent, effect)
    assert again.attempt == 1
    assert calls == 1


def test_receipt_and_claim_contract_exposes_terminal_and_replay_semantics() -> None:
    running = EffectReceipt("effect-1", EffectStatus.RUNNING, intent_id="intent-1", attempt=1)
    assert not running.is_terminal
    assert not running.is_unknown
    assert not running.manual_replay_required
    assert not running.safe_to_retry_automatically
    assert not running.succeeded
    assert running.as_dict()["status"] == "running"
    success = replace(running, status=EffectStatus.SUCCEEDED, result=None)
    assert success.is_terminal
    assert success.succeeded
    assert not success.safe_to_retry_automatically
    assert replace(running, status=EffectStatus.SIMULATED).succeeded
    ambiguous = replace(running, status=EffectStatus.AMBIGUOUS)
    assert ambiguous.is_unknown
    assert ambiguous.manual_replay_required
    assert replace(running, status=EffectStatus.FAILED).safe_to_retry_automatically
    assert EffectClaim(running, acquired=True).owned
    with pytest.raises(ValueError, match="effect_key"):
        EffectReceipt("", EffectStatus.SUCCEEDED)
    with pytest.raises(ValueError, match="attempt"):
        EffectReceipt("effect-1", EffectStatus.SUCCEEDED, attempt=-1)


@pytest.mark.asyncio
async def test_ledger_claim_wait_and_fencing_errors_are_fail_closed() -> None:
    ledger = InMemoryEffectLedger()
    intent = make_intent(intent_id="ledger")
    with pytest.raises(ValueError, match="lease"):
        await ledger.claim(intent, lease_seconds=0)
    first = await ledger.claim(intent, lease_seconds=10, worker_id="worker-a")
    assert first.acquired
    second = await ledger.claim(intent, lease_seconds=10, worker_id="worker-b")
    assert not second.acquired
    assert second.receipt.status is EffectStatus.RUNNING
    timed_out = await ledger.wait(intent.effect_key, timeout=0.001)
    assert timed_out is not None
    assert timed_out.status is EffectStatus.RUNNING
    with pytest.raises(EffectLeaseConflict, match="attempt"):
        await ledger.complete(
            intent,
            attempt=99,
            status=EffectStatus.SUCCEEDED,
            result="bad",
            worker_id="worker-a",
        )
    with pytest.raises(EffectLeaseConflict, match="worker"):
        await ledger.complete(
            intent,
            attempt=1,
            status=EffectStatus.SUCCEEDED,
            result="bad",
            worker_id="worker-b",
        )
    completed = await ledger.complete(
        intent,
        attempt=1,
        status=EffectStatus.SUCCEEDED,
        result="ok",
        worker_id="worker-a",
    )
    assert completed.result == "ok"
    assert await ledger.wait(intent.effect_key) == completed
    assert await ledger.claim(intent) == EffectClaim(completed, acquired=False)
    assert ledger.receipts[intent.effect_key] == completed
    duplicate = await ledger.complete(
        intent,
        attempt=1,
        status=EffectStatus.SUCCEEDED,
        result="changed",
        worker_id="worker-a",
    )
    assert duplicate == completed


@pytest.mark.asyncio
async def test_ledger_rejects_invalid_transitions_and_key_identity_conflicts() -> None:
    ledger = InMemoryEffectLedger()
    intent = make_intent(intent_id="transitions")
    with pytest.raises(ValueError, match="policy records"):
        await ledger.record_policy(intent, status=EffectStatus.SUCCEEDED)
    with pytest.raises(ValueError, match="effect completion"):
        await ledger.complete(intent, attempt=1, status=EffectStatus.RUNNING)
    with pytest.raises(EffectLeaseConflict, match="not claimed"):
        await ledger.complete(intent, attempt=1, status=EffectStatus.FAILED)
    policy = await ledger.record_policy(intent, status=EffectStatus.DENIED)
    assert await ledger.record_policy(intent, status=EffectStatus.SIMULATED) == policy

    other = make_intent(intent_id="other")
    object.__setattr__(other, "effect_key", intent.effect_key)
    assert await ledger.get(other.effect_key) == policy
    with pytest.raises(EffectKeyConflict):
        await ledger.claim(other)


@pytest.mark.asyncio
async def test_deny_and_simulate_never_cross_effect_boundary() -> None:
    ledger = InMemoryEffectLedger()
    executor = ExactlyOnceEffectExecutor(ledger)
    calls: list[str] = []

    async def effect() -> str:
        calls.append("effect")
        return "external"

    denied = await executor.execute(
        make_intent(intent_id="deny", policy_decision=PolicyDecision.DENY), effect
    )
    assert denied.status is EffectStatus.DENIED

    async def simulate() -> dict[str, str]:
        calls.append("simulate")
        return {"would": "create"}

    simulated = await executor.execute(
        make_intent(intent_id="simulate", policy_decision=PolicyDecision.SIMULATE_ONLY),
        effect,
        simulate=simulate,
    )
    assert simulated.status is EffectStatus.SIMULATED
    assert simulated.result == {"would": "create"}
    assert calls == ["simulate"]


@pytest.mark.asyncio
async def test_simulation_without_callback_is_recorded_and_effect_aliases_work() -> None:
    ledger = InMemoryEffectLedger()
    executor = ExactlyOnceEffectExecutor(ledger, worker_id="worker-a")
    simulated = await executor.execute(
        make_intent(intent_id="simulation-empty", policy_decision=PolicyDecision.SIMULATE_ONLY)
    )
    assert simulated.status is EffectStatus.SIMULATED
    calls = 0

    async def effect() -> str:
        nonlocal calls
        calls += 1
        return "done"

    intent = make_intent(intent_id="call-alias")
    with pytest.raises(TypeError, match="effect or call"):
        await executor.execute(intent, effect, call=effect)
    with pytest.raises(ValueError, match="callable"):
        await executor.execute(intent)
    result = await executor.execute(intent, call=effect, worker_id="worker-b")
    assert result.status is EffectStatus.SUCCEEDED
    assert result.worker_id == "worker-b"
    assert calls == 1
    assert executor.effect_key_for(intent) == intent.effect_key


@pytest.mark.asyncio
async def test_confirmation_decision_and_confirmation_alias_are_supported() -> None:
    ledger = InMemoryEffectLedger()
    executor = ExactlyOnceEffectExecutor(ledger)
    intent = make_intent(
        intent_id="confirmation-policy",
        policy_decision=PolicyDecision.REQUIRE_CONFIRMATION,
        risk=IntentRisk.LOW,
    )
    calls = 0

    def sync_effect() -> str:
        nonlocal calls
        calls += 1
        return "ok"

    pending = await executor.execute(intent, sync_effect)
    assert pending.status is EffectStatus.REQUIRE_CONFIRMATION
    done = await executor.execute(
        intent,
        sync_effect,
        confirmation=intent.confirmation_scope(approved_by="operator"),
    )
    assert done.status is EffectStatus.SUCCEEDED
    assert calls == 1


@pytest.mark.asyncio
async def test_running_claim_can_be_observed_without_waiting() -> None:
    ledger = InMemoryEffectLedger()
    first_executor = ExactlyOnceEffectExecutor(ledger, worker_id="worker-a")
    second_executor = ExactlyOnceEffectExecutor(ledger, worker_id="worker-b")
    intent = make_intent(intent_id="no-wait")
    release = asyncio.Event()
    started = asyncio.Event()
    calls = 0

    async def effect() -> str:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return "ok"

    task = asyncio.create_task(first_executor.execute(intent, effect))
    await started.wait()
    observed = await second_executor.execute(intent, effect, wait=False)
    assert observed.status is EffectStatus.RUNNING
    assert observed.attempt == 1
    release.set()
    assert (await task).status is EffectStatus.SUCCEEDED
    assert calls == 1

    # ``wait_timeout`` exercises the bounded wait path while the first worker
    # still holds the key; it must not start a second effect call.
    intent_timeout = make_intent(intent_id="wait-timeout")
    release_timeout = asyncio.Event()
    timeout_started = asyncio.Event()

    async def slow_effect() -> str:
        timeout_started.set()
        await release_timeout.wait()
        return "slow"

    slow_task = asyncio.create_task(first_executor.execute(intent_timeout, slow_effect))
    await timeout_started.wait()
    observed_timeout = await second_executor.execute(
        intent_timeout,
        slow_effect,
        wait_timeout=0.001,
    )
    assert observed_timeout.status is EffectStatus.RUNNING
    release_timeout.set()
    assert (await slow_task).status is EffectStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_high_risk_requires_exact_scope_before_execution() -> None:
    ledger = InMemoryEffectLedger()
    executor = ExactlyOnceEffectExecutor(ledger)
    intent = make_intent(intent_id="pay", risk=IntentRisk.HIGH)
    calls = 0

    async def effect() -> str:
        nonlocal calls
        calls += 1
        return "charged"

    pending = await executor.execute(intent, effect)
    assert pending.status is EffectStatus.REQUIRE_CONFIRMATION
    with pytest.raises(ConfirmationRequired):
        await executor.execute_or_raise(intent, effect)
    wrong_scope = intent.confirmation_scope(approved_by="operator")
    wrong_scope = ConfirmationScope(
        tenant_id=wrong_scope.tenant_id,
        cell_id=wrong_scope.cell_id,
        session_id=wrong_scope.session_id,
        principal_id="different-principal",
        tool_name=wrong_scope.tool_name,
        arguments_hash=wrong_scope.arguments_hash,
        effect_key=wrong_scope.effect_key,
    )
    still_pending = await executor.execute(intent, effect, confirmation_scope=wrong_scope)
    assert still_pending.status is EffectStatus.REQUIRE_CONFIRMATION
    approved = await executor.execute(
        intent,
        effect,
        confirmation_scope=intent.confirmation_scope(approved_by="operator"),
    )
    assert approved.status is EffectStatus.SUCCEEDED
    assert calls == 1


@pytest.mark.asyncio
async def test_unknown_or_ambiguous_result_is_never_auto_replayed() -> None:
    ledger = InMemoryEffectLedger()
    executor = ExactlyOnceEffectExecutor(ledger)
    intent = make_intent(intent_id="send", risk=IntentRisk.LOW)
    calls = 0

    async def uncertain() -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("connection dropped after submission")

    first = await executor.execute(intent, uncertain)
    assert first.status is EffectStatus.AMBIGUOUS
    assert first.manual_replay_required
    second = await executor.execute(intent, uncertain)
    assert second.status is EffectStatus.AMBIGUOUS
    assert calls == 1

    async def confirmed_replay() -> str:
        nonlocal calls
        calls += 1
        return "sent-once-after-review"

    replay = await executor.replay(
        intent,
        confirmed_replay,
        confirmation_scope=intent.confirmation_scope(approved_by="operator"),
    )
    assert replay.status is EffectStatus.SUCCEEDED
    assert replay.replayed
    assert replay.attempt == 2
    assert calls == 2


@pytest.mark.asyncio
async def test_known_failure_is_the_only_automatic_retry_path() -> None:
    ledger = InMemoryEffectLedger()
    executor = ExactlyOnceEffectExecutor(ledger)
    intent = make_intent(intent_id="retryable")
    calls = 0

    async def retryable() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise KnownEffectFailure("provider rejected before applying")
        return "ok"

    failed = await executor.execute(intent, retryable)
    assert failed.status is EffectStatus.FAILED
    succeeded = await executor.execute(intent, retryable)
    assert succeeded.status is EffectStatus.SUCCEEDED
    assert succeeded.attempt == 2
    assert calls == 2


@pytest.mark.asyncio
async def test_expired_running_lease_becomes_ambiguous_and_key_conflicts_are_rejected() -> None:
    ledger = InMemoryEffectLedger()
    executor = ExactlyOnceEffectExecutor(ledger, lease_seconds=0.01)
    intent = make_intent(intent_id="crashed")
    claim = await ledger.claim(intent, lease_seconds=0.001)
    assert claim.acquired
    await asyncio.sleep(0.01)
    receipt = await executor.execute(intent, lambda: "must-not-run")
    assert receipt.status is EffectStatus.AMBIGUOUS
    assert receipt.manual_replay_required

    conflicting = make_intent(intent_id="other", tool_name="different")
    object.__setattr__(conflicting, "effect_key", intent.effect_key)
    with pytest.raises(EffectKeyConflict):
        await ledger.claim(conflicting)


@pytest.mark.asyncio
async def test_confirmation_required_claim_and_policy_state_are_not_bypassed() -> None:
    ledger = InMemoryEffectLedger()
    intent = make_intent(intent_id="ledger-confirm", risk=IntentRisk.HIGH)
    pending = await ledger.record_policy(
        intent,
        status=EffectStatus.REQUIRE_CONFIRMATION,
    )
    assert pending.status is EffectStatus.REQUIRE_CONFIRMATION
    refused = await ledger.claim(intent, confirmation_valid=False)
    assert not refused.acquired
    assert refused.receipt == pending
    approved = await ledger.claim(
        intent,
        confirmation_valid=True,
        worker_id="worker-a",
    )
    assert approved.acquired
    await ledger.complete(
        intent,
        attempt=approved.receipt.attempt,
        status=EffectStatus.FAILED,
        error_type="definitive_rejection",
        worker_id="worker-a",
    )
    retry = await ledger.claim(intent, worker_id="worker-b")
    assert retry.acquired
    await ledger.complete(
        intent,
        attempt=retry.receipt.attempt,
        status=EffectStatus.UNKNOWN,
        error_type="provider_unknown",
        worker_id="worker-b",
    )
    assert not (await ledger.claim(intent)).acquired
    assert not (
        await ledger.claim(
            intent,
            manual_replay=True,
            confirmation_valid=False,
        )
    ).acquired


@pytest.mark.asyncio
async def test_executor_keeps_existing_confirmation_state_for_simulation_variant() -> None:
    ledger = InMemoryEffectLedger()
    executor = ExactlyOnceEffectExecutor(ledger)
    original = make_intent(intent_id="simulation-guard", risk=IntentRisk.HIGH)
    pending = await executor.execute(original, lambda: "must-not-run")
    assert pending.status is EffectStatus.REQUIRE_CONFIRMATION
    simulation = replace_intent_decision(original, PolicyDecision.SIMULATE_ONLY)
    called = False

    async def simulate() -> str:
        nonlocal called
        called = True
        return "simulation"

    kept = await executor.execute(simulation, lambda: "must-not-run", simulate=simulate)
    assert kept.status is EffectStatus.REQUIRE_CONFIRMATION
    assert called is False


@pytest.mark.asyncio
async def test_executor_init_and_explicit_unknown_exceptions_are_safe() -> None:
    with pytest.raises(ValueError, match="lease"):
        ExactlyOnceEffectExecutor(lease_seconds=0)
    with pytest.raises(ValueError, match="worker_id"):
        ExactlyOnceEffectExecutor(worker_id="")

    for error in (UnknownEffectOutcome("unknown"), AmbiguousEffectOutcome("ambiguous")):
        ledger = InMemoryEffectLedger()
        executor = ExactlyOnceEffectExecutor(ledger)
        intent = make_intent(intent_id=type(error).__name__)

        async def effect(error: Exception = error) -> None:
            raise error

        receipt = await executor.execute(intent, effect)
        assert receipt.status is EffectStatus.AMBIGUOUS
        assert receipt.error_type == type(error).__name__
    assert issubclass(UnknownEffectOutcome, EffectExecutionError)


@pytest.mark.asyncio
async def test_effect_completion_cannot_overwrite_another_terminal_state() -> None:
    ledger = InMemoryEffectLedger()
    intent = make_intent(intent_id="terminal-fence")
    await ledger.record_policy(intent, status=EffectStatus.DENIED)
    with pytest.raises(EffectLeaseConflict, match="no longer active"):
        await ledger.complete(intent, attempt=1, status=EffectStatus.SUCCEEDED)
    assert await ledger.wait("missing-effect", timeout=0.001) is None


@pytest.mark.asyncio
async def test_cancelled_effect_is_recorded_ambiguous_before_cancellation_propagates() -> None:
    ledger = InMemoryEffectLedger()
    executor = ExactlyOnceEffectExecutor(ledger)
    intent = make_intent(intent_id="cancelled")
    started = asyncio.Event()

    async def effect() -> None:
        started.set()
        await asyncio.sleep(60)

    task = asyncio.create_task(executor.execute(intent, effect))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    receipt = await ledger.get(intent.effect_key)
    assert receipt is not None
    assert receipt.status is EffectStatus.AMBIGUOUS
