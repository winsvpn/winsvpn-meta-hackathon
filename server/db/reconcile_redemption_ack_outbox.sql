-- Run once with wins-redemption-outbox.timer and its service stopped.
-- This repairs pending mail left by acknowledgments processed before S-HUB-01.
-- It needs redemption_outbox.sealed_secret to exist: the restore runbook adds
-- that column first when a database from an older build lacks it.
--
-- Only rows WITHOUT a sealed mail copy are repaired. Since the welcome mail
-- carries its own sealed copy of the whole key set (K3-04), an acknowledged
-- row that still holds one is legitimate multi-key mail: the API never showed
-- keys 2 and up, so cancelling it would destroy the only way they reach the
-- buyer. Such a row is left pending for the drain.
BEGIN IMMEDIATE;
UPDATE redemption_outbox
SET status = 'cancelled',
    completed_at = (
      SELECT MAX(e.occurred_at) FROM redemption_events AS e
      WHERE e.idempotency_key = redemption_outbox.idempotency_key
        AND e.outcome = 'fulfillment_acknowledged'
    ),
    lease_until = NULL
WHERE status = 'pending'
  AND COALESCE(sealed_secret, '') = ''
  AND EXISTS (
    SELECT 1 FROM redemption_events AS e
    WHERE e.idempotency_key = redemption_outbox.idempotency_key
      AND e.outcome = 'fulfillment_acknowledged'
  );
COMMIT;
