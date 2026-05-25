SELECT o2.id, o2.total
FROM orders o1
JOIN orders o2 ON 1=1
WHERE o1.account_id = 42;
