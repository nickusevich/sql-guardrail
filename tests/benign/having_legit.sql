SELECT account_id, count(*)
FROM orders
WHERE account_id = 42
GROUP BY account_id
HAVING count(*) > 5
LIMIT 10;
