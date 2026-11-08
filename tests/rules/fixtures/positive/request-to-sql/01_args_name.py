def search(request):
    query = request.args.get("q")
    return cursor.execute(query)
