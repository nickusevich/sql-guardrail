SELECT u.id, u.name, o.total
FROM users u
JOIN orders o ON o.account_id = u.id
WHERE o.account_id = 42 AND u.id = 5
LIMIT 50;
