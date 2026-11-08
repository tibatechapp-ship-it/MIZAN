def user_row(uid):
    return cursor.execute("SELECT * FROM users WHERE id = " + uid)
