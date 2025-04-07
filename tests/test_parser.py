import os
import pytest
from datetime import datetime
from nx_logstats.parser import LogParser, LogEntry

# A valid NGINX log line
VALID_LOG_LINE = '127.0.0.1 - - [02/Apr/2025:10:12:01 +0000] "GET /index.html HTTP/1.1" 200 1024'
# An invalid log line
INVALID_LOG_LINE = "Invalid log line with no structure"

def test_parse_valid_line():
    parser = LogParser("dummy.log", ignore_errors=True)
    entry = parser.parse_line(VALID_LOG_LINE)
    assert entry is not None
    assert isinstance(entry, LogEntry)
    assert entry.ip == "127.0.0.1"
    assert entry.method == "GET"
    assert entry.path == "/index.html"
    assert entry.status == 200
    assert entry.bytes_sent == 1024
    expected_ts = LogParser.parse_timestamp("02/Apr/2025:10:12:01")
    assert entry.timestamp == expected_ts

def test_parse_invalid_line():
    parser = LogParser("dummy.log", ignore_errors=True)
    entry = parser.parse_line(INVALID_LOG_LINE)
    assert entry is None

def test_parse_file_valid(tmp_path):
    # Create a temporary file with two valid lines.
    log_content = "\n".join([
        VALID_LOG_LINE,
        '127.0.0.1 - - [02/Apr/2025:10:12:05 +0000] "POST /login HTTP/1.1" 302 512'
    ])
    log_file = tmp_path / "test_valid.log"
    log_file.write_text(log_content)
    
    parser = LogParser(str(log_file))
    entries, error_count = parser.parse()
    assert len(entries) == 2
    assert error_count == 0

def test_parse_file_invalid(tmp_path):
    # One valid line and one invalid line.
    log_content = "\n".join([VALID_LOG_LINE, INVALID_LOG_LINE])
    log_file = tmp_path / "test_invalid.log"
    log_file.write_text(log_content)
    
    parser = LogParser(str(log_file))
    entries, error_count = parser.parse()
    # One valid entry should be parsed, and one error should be counted.
    assert len(entries) == 1
    assert error_count == 1

def test_is_likely_nginx_log(tmp_path):
    # Create a temporary file with an acceptable extension and non-empty content.
    log_file = tmp_path / "sample.log"
    log_file.write_text("\n".join([VALID_LOG_LINE] * 5))
    parser = LogParser(str(log_file))
    assert parser.is_likely_nginx_log() is True

    # Create a file with an acceptable extension but empty content.
    empty_file = tmp_path / "empty.log"
    empty_file.write_text("")
    parser_empty = LogParser(str(empty_file))
    assert parser_empty.is_likely_nginx_log() is False

    # Create a file with a non-accepted extension.
    bad_ext_file = tmp_path / "sample.bad"
    bad_ext_file.write_text("\n".join([VALID_LOG_LINE] * 5))
    parser_bad = LogParser(str(bad_ext_file))
    assert parser_bad.is_likely_nginx_log() is False