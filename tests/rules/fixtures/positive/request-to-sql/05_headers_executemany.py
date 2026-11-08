def run(request):
    stmt = request.headers.get("X-Stmt")
    return conn.executemany(stmt, batch)
