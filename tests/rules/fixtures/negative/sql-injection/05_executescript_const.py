def migrate():
    return conn.executescript(SCHEMA_SQL)
