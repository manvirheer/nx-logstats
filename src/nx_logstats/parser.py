"""
Parser module for nx-logstats

This module provides functionality to parse NGINX access logs.
It handles both well-formed and malformed log entries with appropriate error handling.
"""

import re
import logging
import os
from datetime import datetime
from typing import List, Optional, Tuple

# Set up logger
logger = logging.getLogger(__name__)

# Following regex is a modified version of regex shared in 
# https://hamatti.org/posts/parsing-nginx-server-logs-with-regular-expressions/

NGINX_LOG_PATTERN = (
    r'^(?P<ip>[\d\.:a-fA-F]+) - - \[(?P<timestamp>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?)\] '
    r'"(?P<request>(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) '
    r'(?P<path>[^\s"]+)\s(?P<protocol>HTTP/[\d\.]+))" '  
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)'
)

# Acceptable file extensions
# TODO: Automatically set output format to JSON when writing to a json file, removing the need for the -f json flag.
ACCEPTABLE_EXTENSIONS = ['.log', '.txt', '.text']

# Message to display when a log line doesn't match the expected format.
EXPECTED_FORMAT_MESSAGE = (
    'Accepted format is: <ip> - - [<dd/Mon/YYYY:HH:MM:SS>] "<HTTP_METHOD> <path> HTTP/1.1" <status> <bytes>'
)

class LogEntry:
    """Simple container for a parsed log entry."""
    def __init__(self, ip: str, timestamp: datetime, request: str, method: str,
                 path: str, status: int, bytes_sent: int):
        self.ip = ip
        self.timestamp = timestamp
        self.request = request
        self.method = method
        self.path = path
        self.status = status
        self.bytes_sent = bytes_sent

class LogParser:
    """Handles parsing of an NGINX log file."""
    def __init__(self, filepath: str, ignore_errors: bool = False):
        self.filepath = filepath
        self.ignore_errors = ignore_errors
        self.entries: List[LogEntry] = []
        self.error_count = 0

    @staticmethod
    def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
        # Extract the date and time, ignoring timezone.
        try:
            date_time_part = timestamp_str.split()[0]
            return datetime.strptime(date_time_part, "%d/%b/%Y:%H:%M:%S")
        except Exception as e:
            logger.warning(f"Failed to parse timestamp: {timestamp_str}. Error: {e}")
            return None

    def validate_log_entry(self, data: dict) -> bool:
        # Check that all required fields are present and non-empty.
        for field in ['ip', 'timestamp', 'request', 'method', 'path', 'status', 'bytes']:
            if not data.get(field):
                logger.debug(f"Missing required field: {field}")
                return False
            
        # Validate IP address format
        ip_pattern = (
            r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
            r'([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|'
            r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        )

        if not re.match(ip_pattern, data['ip']):
            logger.debug(f"Invalid IP address format: {data['ip']}")
            return False
        
        # Validate status code (should be 3 digits).
        if not re.match(r'^\d{3}$', str(data['status'])):
            logger.debug(f"Invalid status code: {data['status']}")
            return False
        return True

    def parse_line(self, line: str) -> Optional[LogEntry]:
        # Match the line against the NGINX log pattern.
        match = re.fullmatch(NGINX_LOG_PATTERN, line)

        if not match:
            logger.debug(f"Line does not match pattern: {line}")
            return None
        
        data = match.groupdict()

        # Validate the extracted data.
        if not self.validate_log_entry(data):
            logger.debug(f"Failed validation for line: {line}")
            return None
        
        # Parse the timestamp.
        timestamp = LogParser.parse_timestamp(data['timestamp'])

        if not timestamp:
            logger.debug(f"Failed to parse timestamp in line: {line}")
            return None
        
        # Convert the bytes field, handling the '-' case.
        bytes_sent = int(data['bytes']) if data['bytes'] != '-' else 0

        return LogEntry(
            ip=data['ip'],
            timestamp=timestamp,
            request=data['request'],
            method=data['method'],
            path=data['path'],
            status=int(data['status']),
            bytes_sent=bytes_sent
        )

    def is_likely_nginx_log(self) -> bool:
        # Check if the file extension is acceptable.
        filename = os.path.basename(self.filepath)

        if not any(filename.endswith(ext) for ext in ACCEPTABLE_EXTENSIONS):
            logger.debug(f"File extension not accepted: {filename}")
            return False
        
        # Check if the file is not empty.
        if os.path.getsize(self.filepath) == 0:
            logger.debug(f"File is empty: {self.filepath}")
            return False
        
        return True

    def parse(self) -> Tuple[List[LogEntry], int]:
        # Check if the file is likely an NGINX log file.
        if not self.is_likely_nginx_log():
            logger.error(f"File {self.filepath} is not a valid NGINX log")
            return [], 0
        
        # Open and parse the file line by line.
        try:
            with open(self.filepath, 'r') as file:
                for line_num, line in enumerate(file, 1):
                    line = line.strip()
                    if not line:
                        continue
                    entry = self.parse_line(line)
                    if entry:
                        self.entries.append(entry)
                    else:
                        self.error_count += 1
                        # Warn once about malformed lines.
                        if self.error_count == 1:
                            logger.warning(f"Skipping malformed lines (e.g., line {line_num}). {EXPECTED_FORMAT_MESSAGE}")
        except FileNotFoundError:
            logger.error(f"Log file not found: {self.filepath}")
        except PermissionError:
            logger.error(f"Permission denied for file: {self.filepath}")
        except Exception as e:
            logger.error(f"Error reading file {self.filepath}: {e}")

        # Log info if errors were ignored.
        if self.error_count > 0 and self.ignore_errors:
            logger.info(f"Ignored {self.error_count} malformed lines")

        return self.entries, self.error_count