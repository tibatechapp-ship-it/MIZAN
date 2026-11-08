def view(request):
    return session.query(User).filter_by(uid=request.args.get("id"))
