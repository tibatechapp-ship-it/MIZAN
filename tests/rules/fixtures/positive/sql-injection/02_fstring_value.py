def user_row(name):
    return cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
