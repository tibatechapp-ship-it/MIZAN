def user_row(name):
    return cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))
