SELECT id, total FROM orders
WHERE account_id = 42
  AND id < (SELECT count(*) FROM users LIMIT 1);
