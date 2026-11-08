def rows(request):
    table = request.form["table"]
    return cursor.execute(f"SELECT * FROM {table}")
