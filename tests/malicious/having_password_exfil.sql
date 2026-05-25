SELECT id FROM users
GROUP BY id
HAVING bool_or(substr(password_hash, 1, 1) = 'a');
