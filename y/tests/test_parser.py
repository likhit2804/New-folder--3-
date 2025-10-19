from lib.parser import parse_iac_plan

def test_parse_basic():
    data = {
        "resource_changes": [
            {"type": "aws_s3_bucket", "name": "mybucket", "change": {}}
        ]
    }
    parsed = parse_iac_plan(data)
    assert parsed[0]['type'] == "aws_s3_bucket"
