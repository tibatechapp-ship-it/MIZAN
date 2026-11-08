import tarfile

def unpack(archive, dest):
    with tarfile.open(archive) as tar:
        tar.extractall(path=dest)
