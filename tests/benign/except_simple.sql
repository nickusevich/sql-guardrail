(SELECT id, total FROM orders WHERE account_id = 42 LIMIT 10)
EXCEPT
(SELECT id, total FROM orders WHERE account_id = 42 AND total > 1000 LIMIT 10);
