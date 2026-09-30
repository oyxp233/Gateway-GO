import json
with open('/opt/gateway/appsettings.json', 'r') as f:
    d = json.load(f)
d['Gateway']['DisableAdminHttp'] = True
with open('/opt/gateway/appsettings.json', 'w') as f:
    json.dump(d, f, indent=2)
print('OK')
