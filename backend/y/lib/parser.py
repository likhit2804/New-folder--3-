import json

# backend/y/lib/parser.py
import json

def parse_iac_plan(iac_json):
    resources = []
    # CORRECTED: Traverse through the nested structure to find the resources
    root_module = iac_json.get('planned_values', {}).get('root_module', {})
    for res in root_module.get('resources', []):
        resource = {
            # Use the 'type' and 'name' directly from the resource object
            'type': res.get('type'),
            'name': res.get('name'),
            # Pass the entire 'values' dictionary for context
            'change': res.get('values', {}),
        }
        resources.append(resource)
    return resources