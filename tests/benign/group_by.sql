SELECT product_name, SUM(total) AS revenue
FROM orders
WHERE account_id = 42
GROUP BY product_name
ORDER BY revenue DESC
LIMIT 10;
