from flask import request
import subprocess

def handle_request():
    cmd = request.args.get("cmd")
    run_command(cmd)

def run_command(user_cmd):
    subprocess.run(user_cmd, shell=True)

def safe_handler():
    data = "static"
    process(data)

def process(value):
    print(value)
