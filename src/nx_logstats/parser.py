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
ACCEPTABLE_EXTENSIONS = ['.log', '.txt', '.text', '.log.gz', '.log.1']


class LogEntry:
    """
    Parsed log entry with structured fields.
    Handles standard NGINX access log format with IP, timestamp, request, status, and bytes.
    """
    def __init__(
        self,
        ip: str,
        timestamp: datetime,
        request: str,
        method: str,
        path: str,
        status: int,
        bytes_sent: int
    ):
        self.ip = ip
        self.timestamp = timestamp
        self.request = request
        self.method = method
        self.path = path
        self.status = status
        self.bytes_sent = bytes_sent


class LogParser:
    """
    Encapsulates the functionality to parse an NGINX log file.
    This class handles file type checking, line parsing, and aggregate processing.
    """
    def __init__(self, filepath: str, ignore_errors: bool = False):
        self.filepath = filepath
        self.ignore_errors = ignore_errors
        self.entries: List[LogEntry] = []
        self.error_count: int = 0

    # Defining a static method to parse the timestamp
    @staticmethod
    def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
        """
        Parse a timestamp string into a datetime object.
        Uses the standard NGINX timestamp format.
        """
        try:
            # Extract the date and time part, ignoring timezone if present
            date_time_part = timestamp_str.split()[0]
            return datetime.strptime(date_time_part, "%d/%b/%Y:%H:%M:%S")
        except (ValueError, IndexError) as e:
            logger.warning(f"Failed to parse timestamp: {timestamp_str}. Error: {e}")
            return None

    def validate_log_entry(self, data: dict) -> bool:
        """
        Perform additional validation on the parsed data to ensure it's a valid log entry.
        
        Args:
            data: Dictionary containing the parsed log entry fields
            
        Returns:
            bool: True if the entry passes validation, False otherwise
        """
        # Check that required fields are present and non-empty
        required_fields = ['ip', 'timestamp', 'request', 'method', 'path', 'status', 'bytes']
        for field in required_fields:
            if field not in data or not data[field]:
                logger.debug(f"Missing required field: {field}")
                return False
        
        # Validate IP address format
        ip_pattern = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        if not re.match(ip_pattern, data['ip']):
            logger.debug(f"Invalid IP address format: {data['ip']}")
            return False
            
        # Validate status code (should be 3 digits)
        if not re.match(r'^\d{3}$', str(data['status'])):
            logger.debug(f"Invalid status code: {data['status']}")
            return False
            
        return True

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single log line into a structured LogEntry object.
        
        Args:
            line: A single line from the log file
            
        Returns:
            LogEntry object if parsing succeeds, None otherwise
        """
        try:
            match = re.match(NGINX_LOG_PATTERN, line)
            if not match:
                logger.debug(f"Line does not match NGINX log pattern: {line}")
                return None

            data = match.groupdict()
            
            # Additional validation
            if not self.validate_log_entry(data):
                logger.debug(f"Failed validation for line: {line}")
                return None

            timestamp = self.parse_timestamp(data['timestamp'])
            if not timestamp:
                logger.debug(f"Failed to parse timestamp in line: {line}")
                return None

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
        except Exception as e:
            logger.error(f"Error parsing line: {line}. Error: {e}")
            return None

    def is_likely_nginx_log(self) -> bool:
        """
        Check if the file is likely to be an NGINX log based on its extension and sample content.
        
        Returns:
            bool: True if the file appears to be an NGINX log, False otherwise
        """
        # First check the file extension
        filename = os.path.basename(self.filepath)
        extension_match = False
        for ext in ACCEPTABLE_EXTENSIONS:
            if filename.endswith(ext):
                extension_match = True
                break
                
        if not extension_match:
            logger.debug(f"File extension not recognized as a log file: {filename}")
            return False
            
        # Then check the content
        try:
            with open(self.filepath, 'r') as file:
                # Read up to 10 non-empty lines
                sample_lines = []
                for _ in range(10):
                    line = file.readline().strip()
                    if line:
                        sample_lines.append(line)
                
                if not sample_lines:
                    logger.warning("File is empty")
                    return False
                    
                # Check if at least 50% of lines match the NGINX log pattern
                match_count = sum(1 for line in sample_lines if re.match(NGINX_LOG_PATTERN, line))
                match_percentage = (match_count / len(sample_lines)) * 100
                
                if match_percentage >= 50:
                    logger.debug(f"{match_percentage:.1f}% of sample lines match NGINX log pattern")
                    return True
                else:
                    logger.debug(f"Only {match_percentage:.1f}% of sample lines match NGINX log pattern")
                    return False
                    
        except Exception as e:
            logger.warning(f"Unable to check content of {self.filepath}: {e}")
            # Don't accept based solely on extension anymore
            return False

    def parse(self) -> Tuple[List[LogEntry], int]:
        """
        Parse the log file and return a tuple containing:
          - A list of valid LogEntry objects.
          - The count of malformed or unrecognized lines.
        """
        try:
            # First check if this is likely an NGINX log file
            if not self.is_likely_nginx_log():
                logger.error(f"File {self.filepath} does not appear to be a valid NGINX log file")
                logger.error("If you believe this is a valid NGINX log file, check the format and try again")
                return [], 0
                
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
                        if not self.ignore_errors:
                            logger.warning(f"Skipping malformed line {line_num}: {line[:80]}...")
        except FileNotFoundError:
            logger.error(f"Log file not found: {self.filepath}")
        except PermissionError:
            logger.error(f"Permission denied when accessing: {self.filepath}")
        except Exception as e:
            logger.error(f"Unexpected error when opening log file: {e}")

        if self.error_count > 0:
            if self.ignore_errors:
                logger.info(f"Ignored {self.error_count} malformed lines while processing")
                
        return self.entries, self.error_count