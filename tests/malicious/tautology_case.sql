SELECT id, name FROM users WHERE id = 1 OR (CASE WHEN 0 = 1 THEN false ELSE true END) LIMIT 10;
