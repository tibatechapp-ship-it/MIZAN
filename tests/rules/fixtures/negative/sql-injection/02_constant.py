ALL_USERS = "SELECT * FROM users"

def rows():
    return cursor.execute(ALL_USERS)
