import pytest
from datetime import datetime
from nx_logstats.parser import LogEntry
from nx_logstats.analysis import LogAnalyzer

@pytest.fixture
def sample_entries():
    return [
        LogEntry("127.0.0.1", datetime(2025, 4, 2, 10, 12, 1), "GET /index.html HTTP/1.1", "GET", "/index.html", 200, 1024),
        LogEntry("127.0.0.1", datetime(2025, 4, 2, 10, 12, 5), "POST /login HTTP/1.1", "POST", "/login", 302, 512),
        LogEntry("127.0.0.1", datetime(2025, 4, 2, 10, 12, 7), "GET /dashboard HTTP/1.1", "GET", "/dashboard", 200, 1536),
        LogEntry("127.0.0.1", datetime(2025, 4, 2, 10, 12, 9), "GET /settings HTTP/1.1", "GET", "/settings", 404, 256)
    ]

def test_total_request_count(sample_entries):
    analyzer = LogAnalyzer(sample_entries)
    assert analyzer.total_request_count() == 4

def test_status_code_distribution(sample_entries):
    analyzer = LogAnalyzer(sample_entries)
    dist = analyzer.status_code_distribution()
    assert dist[200] == 2
    assert dist[302] == 1
    assert dist[404] == 1

def test_average_response_size(sample_entries):
    analyzer = LogAnalyzer(sample_entries)
    avg = analyzer.average_response_size()
    expected_avg = (1024 + 512 + 1536 + 256) / 4
    assert abs(avg - expected_avg) < 0.1

def test_http_method_distribution(sample_entries):
    analyzer = LogAnalyzer(sample_entries)
    dist = analyzer.http_method_distribution()
    assert dist["GET"] == 3
    assert dist["POST"] == 1

def test_top_endpoints(sample_entries):
    analyzer = LogAnalyzer(sample_entries)
    endpoints = analyzer.top_endpoints()
    # Endpoints should be returned as a list of tuples (path, count)
    assert len(endpoints) == 4
    # First endpoint should be the most common one
    assert endpoints[0][0] in ["/index.html", "/dashboard", "/settings", "/login"]

def test_request_volume_by_hour(sample_entries):
    analyzer = LogAnalyzer(sample_entries)
    hourly = analyzer.request_volume_by_hour()
    # All sample entries have the same hour (10)
    assert hourly[10] == 4