SELECT id, total FROM orders WHERE COALESCE(account_id, 42) = 42 LIMIT 10;
