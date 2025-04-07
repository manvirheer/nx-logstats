import json
import pytest
import tempfile
from nx_logstats.reporter import Reporter

@pytest.fixture
def dummy_summary():
    return {
        'total_requests': 4,
        'status_codes': {200: 2, 302: 1, 404: 1},
        'top_endpoints': [('/index.html', 2), ('/login', 1), ('/dashboard', 1)],
        'http_methods': {'GET': 3, 'POST': 1},
        'hourly_request_volume': {10: 4},
        'avg_response_size': 832.0
    }

def test_generate_text_report(dummy_summary):
    reporter = Reporter(dummy_summary)
    text_report = reporter.generate_text_report()
    assert "NGINX ACCESS LOG ANALYSIS REPORT" in text_report
    assert "Total Requests:" in text_report

def test_generate_json_report(dummy_summary):
    reporter = Reporter(dummy_summary)
    json_report = reporter.generate_json_report()
    data = json.loads(json_report)
    assert "generated_at" in data
    assert "metrics" in data
    assert data["metrics"]["total_requests"] == 4

def test_output_to_file(dummy_summary):
    with tempfile.NamedTemporaryFile(suffix='.txt') as tmp:
        reporter = Reporter(dummy_summary)
        success = reporter.output_to_file(tmp.name)
        assert success
        with open(tmp.name, 'r') as f:
            content = f.read()
            assert "NGINX ACCESS LOG ANALYSIS REPORT" in content

def test_output_to_file_json(dummy_summary):
    with tempfile.NamedTemporaryFile(suffix='.json') as tmp:
        reporter = Reporter(dummy_summary)
        success = reporter.output_to_file(tmp.name, format='json')
        assert success
        with open(tmp.name, 'r') as f:
            content = f.read()
            data = json.loads(content)
            assert "metrics" in data
            assert data["metrics"]["total_requests"] == 4