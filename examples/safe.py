import json
import os
import subprocess

password = os.environ.get("APP_PASSWORD")

def handle(command, serialized):
    subprocess.run(["printf", "%s", command], shell=False)
    return json.loads(serialized)
