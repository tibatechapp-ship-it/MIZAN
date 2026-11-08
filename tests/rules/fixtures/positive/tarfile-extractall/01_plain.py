import tarfile

with tarfile.open(path) as tar:
    tar.extractall()
