SELECT id FROM orders WHERE account_id = 42
UNION
SELECT id FROM orders WHERE account_id = 42
OFFSET 999999999
