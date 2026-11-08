def view(request):
    q = request.GET["q"]
    return cursor.execute(q)
