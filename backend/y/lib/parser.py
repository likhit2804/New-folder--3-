import json

def parse_iac_plan(plan_data):
    """
    Parses a Terraform JSON plan and extracts all resources
    and their planned values into a simple list of dicts.
    
    This fulfills Phase I, Step 2 of the project plan.
    """
    print("Parsing IaC plan...")
    parsed_resources = []

    try:
        # 1. Look for resources in 'planned_values' (for new resources)
        if 'planned_values' in plan_data and 'root_module' in plan_data['planned_values']:
            resources = plan_data['planned_values']['root_module'].get('resources', [])
            for res in resources:
                # Add 'name' and 'type' for the explanation builder
                res['values']['name'] = res.get('name')
                res['values']['type'] = res.get('type')
                res['values']['address'] = res.get('address')
                parsed_resources.append(res['values'])

        # 2. Look for resources in 'resource_changes' (for modified resources)
        if 'resource_changes' in plan_data:
            for res_change in plan_data.get('resource_changes', []):
                # We only care about create or update
                if 'create' in res_change.get('action', []) or 'update' in res_change.get('action', []):
                    change = res_change.get('change', {})
                    after = change.get('after', {})
                    if after:
                        # Add 'name' and 'type' for the explanation builder
                        after['name'] = res_change.get('name')
                        after['type'] = res_change.get('type')
                        after['address'] = res_change.get('address')
                        parsed_resources.append(after)

        print(f"Parsed {len(parsed_resources)} resources from plan.")
        return parsed_resources
        
    except Exception as e:
        print(f"Error parsing IaC plan: {e}")
        return []