import json
import os

app_name = '/'.join(os.path.dirname(os.path.realpath(__file__)).split('/')[:-1])


with open(app_name + '/settings.json') as f:
    conf_settings = json.load(f)

with open(app_name + '/conf.json') as f:
    conf = json.loads(f.read())

mongoconfig = conf.get("mongoconfig")

mongoconfig['connection_url'] = conf_settings.get('mongo').get('connection_url')