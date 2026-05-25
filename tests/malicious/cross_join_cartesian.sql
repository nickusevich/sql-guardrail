SELECT o2.id, o2.total
FROM orders o1
CROSS JOIN orders o2
WHERE o1.account_id = 42 AND o2.account_id = 42;
