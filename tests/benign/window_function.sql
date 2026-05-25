SELECT
    id,
    total,
    ROW_NUMBER() OVER (PARTITION BY product_name ORDER BY created_at DESC) AS rn
FROM orders
WHERE account_id = 42
LIMIT 100;
