"""
Parser module for nx-logstats

This module provides functionality to parse NGINX access logs.
It handles both well-formed and malformed log entries with appropriate error handling.
"""

import re
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

# Set up logger
logger = logging.getLogger(__name__)


# Following regex is a modified version of regex shared in  https://hamatti.org/posts/parsing-nginx-server-logs-with-regular-expressions/
# Matches: IP, timestamp, method, path, protocol, status, bytes
NGINX_LOG_PATTERN = r'^(?P<ip>[\d\.:a-fA-F]+) - - \[(?P<timestamp>.*?)\] "(?P<request>(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)?\s?(?P<path>[^"]*?)(?:\s(?P<protocol>HTTP/[\d\.]+))?)?" (?P<status>\d+) (?P<bytes>\d+|-)'

# Acceptable file extensions
ACCEPTABLE_EXTENSIONS = ['.log', '.txt', '.text', '.log.gz', '.log.1']

class LogEntry:
    """
    Parsed log entry with structured fields.
    Handles standard NGINX access log format with IP, timestamp, request, status, and bytes.
    """
    
    def __init__(self, 
                 ip: str, 
                 timestamp: datetime, 
                 request: str,
                 method: str,
                 path: str,
                 status: int, 
                 bytes_sent: int):
        self.ip = ip
        self.timestamp = timestamp
        self.request = request
        self.method = method
        self.path = path
        self.status = status
        self.bytes_sent = bytes_sent

def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    # Parse a timestamp string into a datetime object
    try:
        # Standard NGINX timestamp format
        return datetime.strptime(timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError) as e:
        logger.warning(f"Failed to parse timestamp: {timestamp_str}. Error: {e}")
        return None

def parse_line(line: str) -> Optional[LogEntry]:
    # Parse a single log line into a structured LogEntry object
    try:
        match = re.match(NGINX_LOG_PATTERN, line)
        if not match:
            logger.warning(f"Malformed log line: {line}")
            return None
            
        # Use named groups from regex
        data = match.groupdict()
        
        # Parse timestamp
        timestamp = parse_timestamp(data['timestamp'])
        if not timestamp:
            return None
            
        # Handle '-' for bytes_sent
        if data['bytes'] == '-':
            bytes_sent = 0
        else:
            bytes_sent = int(data['bytes'])
        
        # Default method/path if not present
        method = data.get('method', '')
        path = data.get('path', '')
        if method is None:
            method = ''
        if path is None:
            path = ''
            
        return LogEntry(
            ip=data['ip'],
            timestamp=timestamp,
            request=data['request'],
            method=method,
            path=path,
            status=int(data['status']),
            bytes_sent=bytes_sent
        )
    except Exception as e:
        logger.error(f"Error parsing line: {line}. Error: {e}")
        return None

def is_likely_nginx_log(filepath: str) -> bool:
    # Check if the file is likely to be an NGINX log based on extension and content
    filename = os.path.basename(filepath)
    
    # Check file extension
    for ext in ACCEPTABLE_EXTENSIONS:
        if filename.endswith(ext):
            # Check content sample
            try:
                with open(filepath, 'r') as file:
                    # Read first few lines
                    sample_lines = []
                    for _ in range(5):
                        line = file.readline().strip()
                        if line:  # Skip empty lines
                            sample_lines.append(line)
                    
                    # Check if any line matches NGINX pattern
                    if any(re.match(NGINX_LOG_PATTERN, line) for line in sample_lines):
                        return True
            except Exception as e:
                logger.warning(f"Unable to check content of {filepath}: {e}")
                # Accept based on extension
                return True
    
    return False

def parse_log_file(filepath: str, ignore_errors: bool = False) -> tuple[List[LogEntry], int]:
    # Parse a log file and return a list of valid LogEntry objects and count of errors
    entries = []
    error_count = 0
    
    try:
        with open(filepath, 'r') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if not line:  # Skip empty lines
                    continue
                    
                try:
                    entry = parse_line(line)
                    if entry:
                        entries.append(entry)
                    else:
                        error_count += 1
                        if not ignore_errors:
                            logger.warning(f"Skipping malformed line {line_num}: {line[:80]}...")
                except Exception as e:
                    error_count += 1
                    if not ignore_errors:
                        logger.error(f"Error processing line {line_num}: {e}")
    except FileNotFoundError:
        logger.error(f"Log file not found: {filepath}")
    except PermissionError:
        logger.error(f"Permission denied when accessing: {filepath}")
    except Exception as e:
        logger.error(f"Unexpected error when opening log file: {e}")
    
    if error_count > 0:
        if ignore_errors:
            logger.info(f"Ignored {error_count} malformed lines while processing")
        else:
            logger.warning(f"Encountered {error_count} malformed lines while processing")
            logger.warning("Use --ignore-errors to suppress these warnings and continue processing")
    
    return entries, error_count