from lib.risk_scoring import calculate_risk

def test_score_high_risk():
    res = {'type': 'aws_s3_bucket', 'name': 'public-bucket'}
    threat_data = {'risk_level': 'high', 'feed': 'mock'}
    assert calculate_risk(res, threat_data) >= 8
