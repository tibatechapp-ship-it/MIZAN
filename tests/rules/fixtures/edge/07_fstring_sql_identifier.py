def rows(table):
    return cursor.execute(f"SELECT * FROM {table}")
