SELECT 1 FROM users HAVING max(password_hash) IS NOT NULL;
