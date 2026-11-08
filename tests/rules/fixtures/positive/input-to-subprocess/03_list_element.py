import subprocess

name = input()
subprocess.call(["sh", "-c", name])
