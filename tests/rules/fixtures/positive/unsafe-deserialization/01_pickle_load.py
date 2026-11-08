import pickle

def load(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)
