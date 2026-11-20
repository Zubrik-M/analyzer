import pickle
import subprocess

password = "demo-only-secret"

def handle(command, serialized):
    subprocess.run(command, shell=True)
    return pickle.loads(serialized)
