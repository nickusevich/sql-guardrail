(SELECT id, total FROM orders WHERE account_id = 42 LIMIT 10)
INTERSECT
(SELECT id, total FROM orders WHERE account_id = 42 AND total > 100 LIMIT 10);
