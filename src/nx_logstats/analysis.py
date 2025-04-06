"""
Analysis module for nx-logstats

This module provides functionality to analyze parsed log entries and 
extract meaningful metrics and statistics.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

import pandas as pd

from nx_logstats.parser import LogEntry

# Set up logger
logger = logging.getLogger(__name__)

class LogAnalyzer:
    """
    Analyzes log entries to extract insights.
    Provides metrics for status codes, endpoints, request volume, 
    HTTP methods, and response size from standard NGINX access logs.
    """
    
    def __init__(self, entries: List[LogEntry]):
        self.entries = entries
        logger.info(f"Initialized analyzer with {len(entries)} log entries")
        
        # Convert to DataFrame for easier analysis
        if entries:
            self.df = self.create_dataframe()
        else:
            self.df = pd.DataFrame()
            
    def create_dataframe(self) -> pd.DataFrame:
        # Convert log entries to a pandas DataFrame for analysis
        data = {
            'ip': [],
            'timestamp': [],
            'method': [],
            'path': [],
            'status': [],
            'bytes_sent': []
        }
        
        for entry in self.entries:
            data['ip'].append(entry.ip)
            data['timestamp'].append(entry.timestamp)
            data['method'].append(entry.method)
            data['path'].append(entry.path)
            data['status'].append(entry.status)
            data['bytes_sent'].append(entry.bytes_sent)
            
        df = pd.DataFrame(data)
        logger.debug(f"Created DataFrame with shape {df.shape}")
        return df
        
    def status_code_distribution(self) -> Dict[int, int]:
        # Count occurrences of each HTTP status code
        if self.df.empty:
            logger.warning("No data available for status code analysis")
            return {}
        
        try:
            status_counts = self.df['status'].value_counts().to_dict()
            logger.info(f"Found {len(status_counts)} unique status codes")
            return status_counts
        except Exception as e:
            logger.error(f"Error analyzing status codes: {e}")
            return {}
            
    def top_endpoints(self, n: int = 10) -> List[Tuple[str, int]]:
        # Find the most frequently accessed endpoints
        if self.df.empty:
            logger.warning("No data available for endpoint analysis")
            return []
            
        try:
            endpoint_counts = self.df['path'].value_counts().head(n).to_dict()
            return [(endpoint, count) for endpoint, count in endpoint_counts.items()]
        except Exception as e:
            logger.error(f"Error analyzing top endpoints: {e}")
            return []
            
    def request_volume_by_hour(self) -> Dict[int, int]:
        # Calculate request volume by hour of day
        if self.df.empty:
            logger.warning("No data available for hourly analysis")
            return {}
            
        try:
            self.df['hour'] = self.df['timestamp'].apply(lambda x: x.hour)
            hourly_counts = self.df['hour'].value_counts().sort_index().to_dict()
            logger.info(f"Analyzed request volume across {len(hourly_counts)} hours")
            return hourly_counts
        except Exception as e:
            logger.error(f"Error analyzing hourly request volume: {e}")
            return {}
            
    def total_request_count(self) -> int:
        # Get the total number of requests
        return len(self.entries)
        
    def average_response_size(self) -> float:
        # Calculate the average response size in bytes
        if self.df.empty:
            logger.warning("No data available for response size analysis")
            return 0.0
            
        try:
            avg_bytes = self.df['bytes_sent'].mean()
            logger.info(f"Calculated average response size: {avg_bytes:.2f} bytes")
            return avg_bytes
        except Exception as e:
            logger.error(f"Error calculating average response size: {e}")
            return 0.0
            
    def http_method_distribution(self) -> Dict[str, int]:
        # Count occurrences of each HTTP method (GET, POST, etc.)
        if self.df.empty:
            logger.warning("No data available for HTTP method analysis")
            return {}
            
        try:
            method_counts = self.df['method'].value_counts().to_dict()
            logger.info(f"Found {len(method_counts)} unique HTTP methods")
            return method_counts
        except Exception as e:
            logger.error(f"Error analyzing HTTP methods: {e}")
            return {}
            
    def get_summary(self, top_n: int = 10) -> Dict[str, Any]:
        # Generate a comprehensive summary of log analysis
        return {
            'total_requests': self.total_request_count(),
            'status_codes': self.status_code_distribution(),
            'top_endpoints': self.top_endpoints(top_n),
            'http_methods': self.http_method_distribution(),
            'hourly_request_volume': self.request_volume_by_hour(),
            'avg_response_size': self.average_response_size()
        }