import json

def parse_iac_plan(iac_json):
    resources = []
    for res in iac_json.get('resource_changes', []):
        resource = {
            'type': res['type'],
            'name': res['name'],
            'change': res['change'],
        }
        resources.append(resource)
    return resources
