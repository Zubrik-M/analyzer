value = input()
cursor.execute("SELECT * FROM users WHERE id=?", (value,))
