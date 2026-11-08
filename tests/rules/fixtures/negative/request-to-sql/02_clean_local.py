def view(request):
    q = "SELECT count(*) FROM events"
    return cursor.execute(q)
