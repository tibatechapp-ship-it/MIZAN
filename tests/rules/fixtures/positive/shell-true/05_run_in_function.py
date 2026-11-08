import subprocess

def deploy(target):
    subprocess.run(["tar", "czf", target], shell=True)
