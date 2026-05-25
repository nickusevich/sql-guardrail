WITH recent_orders AS (
    SELECT id, total, created_at
    FROM orders
    WHERE account_id = 42 AND created_at > '2026-01-01'
    LIMIT 1000
)
SELECT id, total FROM recent_orders;
