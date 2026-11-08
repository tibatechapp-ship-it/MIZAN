import subprocess
import sys

target = sys.argv[1]
subprocess.run(target, shell=True)
