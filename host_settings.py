import json
with open('host_settings.json', 'r') as f:
    host_config = json.load(f)
host=host_config["host"]
port=host_config["port"]