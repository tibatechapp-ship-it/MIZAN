def logs(tag):
    return cursor.execute("SELECT * FROM logs WHERE tag = %s" % tag)
