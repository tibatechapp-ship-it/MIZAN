def rows(table):
    return cursor.execute(f"SELECT * FROM {table} WHERE active = 1")
