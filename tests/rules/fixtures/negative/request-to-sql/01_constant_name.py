QUERY = "SELECT * FROM metrics"

def view(request):
    return cursor.execute(QUERY)
