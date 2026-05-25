SELECT id FROM users WHERE id = 1 AND pg_sleep(10) IS NOT NULL;
