import zipfile

with zipfile.ZipFile(path) as zf:
    zf.extractall()
