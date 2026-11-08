import ssl

def lax_context():
    return ssl._create_unverified_context()
