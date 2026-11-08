def view(request):
    uid = request.args.get("id")
    return cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
