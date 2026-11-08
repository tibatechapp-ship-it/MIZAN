def view(request):
    mode = request.method
    return cursor.execute(VIEW_SQL[mode])
