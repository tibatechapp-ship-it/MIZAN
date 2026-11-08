def purge(sid):
    return self.cursor.execute("DELETE FROM sessions WHERE id = " + sid)
