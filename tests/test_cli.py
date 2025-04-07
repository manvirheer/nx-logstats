import sys
import pytest
from nx_logstats.cli import main

def test_cli_with_valid_log(tmp_path):
    # Create a temporary valid log file.
    log_content = "\n".join([
        '127.0.0.1 - - [02/Apr/2025:10:12:01 +0000] "GET /index.html HTTP/1.1" 200 1024',
        '127.0.0.1 - - [02/Apr/2025:10:12:05 +0000] "POST /login HTTP/1.1" 302 512'
    ])
    log_file = tmp_path / "valid_simple_logs.log"
    log_file.write_text(log_content)
    
    # Run CLI increased verbosity.
    args = [str(log_file), "-v"]
    exit_code = main(args)
    assert exit_code == 0

def test_cli_with_invalid_log(tmp_path):
    # Create a temporary log file with one invalid log line.
    log_content = "\n".join([
        "Invalid log line with no structure",
        '127.0.0.1 - - [02/Apr/2025:10:12:01 +0000] "GET /index.html HTTP/1.1" 200 1024'
    ])
    log_file = tmp_path / "errors_nginx_logs.log"
    log_file.write_text(log_content)
    
    # Without --ignore-errors, expect a non-zero exit code.
    args = [str(log_file)]
    exit_code = main(args)
    assert exit_code != 0

def test_cli_with_output_file(tmp_path):
    # Create a temporary valid log file.
    log_content = "\n".join([
        '127.0.0.1 - - [02/Apr/2025:10:12:01 +0000] "GET /index.html HTTP/1.1" 200 1024',
        '127.0.0.1 - - [02/Apr/2025:10:12:05 +0000] "POST /login HTTP/1.1" 302 512'
    ])
    log_file = tmp_path / "valid_logs.log"
    log_file.write_text(log_content)
    
    # Create an output file path
    output_file = tmp_path / "report.txt"
    
    # Run CLI with output file and ignore-errors flag
    args = [str(log_file), "--output", str(output_file), "--ignore-errors"]
    exit_code = main(args)
    assert exit_code == 0
    assert output_file.exists()