import os
import pytest
from pathlib import Path
from nx_logstats.cli import main

def get_sample_logs_dir():
    """Find the sample_logs directory relative to the test file."""
    # Start with the directory of this test file
    current_dir = Path(__file__).parent
    
    # Look for sample_logs in parent directory (project root)
    project_root = current_dir.parent
    sample_logs_dir = project_root / "sample_logs"
    
    if sample_logs_dir.exists() and sample_logs_dir.is_dir():
        return sample_logs_dir
    
    # If not found, raise an error
    raise FileNotFoundError(f"Sample logs directory not found at {sample_logs_dir}")

@pytest.mark.parametrize("sample_log, expected_success", [
    ("valid_simple_logs.txt", True),
    ("valid_long_logs.txt", True),
    ("errors_nginx_logs.txt", False),  
    ("errors_small_dataset.txt", False)
])
def test_integration_sample_logs(sample_log, expected_success):
    """Test the CLI with actual sample log files from the sample_logs directory."""
    sample_logs_dir = get_sample_logs_dir()
    log_file = sample_logs_dir / sample_log
    
    # Verify the sample log file exists
    assert log_file.exists(), f"Sample log file not found: {log_file}"
    
    args = [str(log_file)]
    
    exit_code = main(args)
    if expected_success:
        assert exit_code == 0
    else:
        assert exit_code != 0