import ssl

ctx = ssl._create_unverified_context()
conn = connect(host, context=ctx)
