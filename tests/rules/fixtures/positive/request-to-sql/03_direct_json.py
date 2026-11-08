def handler(request):
    return cursor.execute(request.json["q"])
