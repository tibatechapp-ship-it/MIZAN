def insert(params):
    return conn.execute("INSERT INTO t VALUES (?, ?)", params)
