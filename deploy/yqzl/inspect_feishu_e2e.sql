\pset tuples_only on
\pset format unaligned

SELECT concat(
         'inbound|total=', count(*),
         '|unique_external=', count(DISTINCT external_message_id),
         '|latest=', coalesce(max(accepted_at)::text, 'none')
       )
  FROM inbound_messages
 WHERE tenant_id = 'nstarzx-feishu';

SELECT concat('inbound_status|', status, '=', count(*))
  FROM inbound_messages
 WHERE tenant_id = 'nstarzx-feishu'
 GROUP BY status
 ORDER BY status;

SELECT concat(
         'inbound_type|kind=', coalesce(envelope_json->>'payload_kind', 'none'),
         '|event=', coalesce(envelope_json->>'event_type', 'none'),
         '|total=', count(*)
       )
  FROM inbound_messages
 WHERE tenant_id = 'nstarzx-feishu'
 GROUP BY envelope_json->>'payload_kind', envelope_json->>'event_type'
 ORDER BY envelope_json->>'payload_kind', envelope_json->>'event_type';

SELECT concat('turn_status|', status, '=', count(*))
  FROM session_turns
 WHERE tenant_id = 'nstarzx-feishu'
 GROUP BY status
 ORDER BY status;

SELECT concat('session_events|total=', count(*))
  FROM session_events
 WHERE tenant_id = 'nstarzx-feishu';

SELECT concat('outbound_status|', status, '=', count(*))
  FROM outbound_messages
 WHERE tenant_id = 'nstarzx-feishu'
 GROUP BY status
 ORDER BY status;

SELECT concat(
         'delivery|status=', status,
         '|provider_code=', coalesce(provider_code, 'none'),
         '|attempts=', count(*),
         '|latest=', coalesce(max(completed_at)::text, 'none')
       )
  FROM delivery_attempts
 WHERE tenant_id = 'nstarzx-feishu'
 GROUP BY status, provider_code
 ORDER BY status, provider_code;

SELECT concat('outbox_unpublished|total=', count(*))
  FROM outbox_events
 WHERE tenant_id = 'nstarzx-feishu'
   AND published_at IS NULL;

SELECT concat('dead_letter|', status, '|reason=', reason, '|total=', count(*))
  FROM dead_letters
 WHERE tenant_id = 'nstarzx-feishu'
 GROUP BY status, reason
 ORDER BY status, reason;
