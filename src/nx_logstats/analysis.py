"""
Analysis module for nx-logstats

This module provides functionality to analyze parsed log entries and extract meaningful metrics.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple

import pandas as pd

from nx_logstats.parser import LogEntry

logger = logging.getLogger(__name__)


class LogAnalyzer:
    """
    Analyzes log entries to extract metrics like status codes, endpoints, hourly volume,
    HTTP methods, and average response size.
    """
    
    def __init__(self, entries: List[LogEntry]):
        self.entries = entries
        logger.info(f"Initialized analyzer with {len(entries)} log entries")
        # Create a DataFrame if entries are present
        self.df = self.create_dataframe() if entries else pd.DataFrame()

    def create_dataframe(self) -> pd.DataFrame:
        # Build the DataFrame using list comprehensions for simplicity
        data = {
            'ip': [entry.ip for entry in self.entries],
            'timestamp': [entry.timestamp for entry in self.entries],
            'method': [entry.method for entry in self.entries],
            'path': [entry.path for entry in self.entries],
            'status': [entry.status for entry in self.entries],
            'bytes_sent': [entry.bytes_sent for entry in self.entries]
        }
        
        df = pd.DataFrame(data)
        logger.debug(f"Created DataFrame with shape {df.shape}")
        return df

    def status_code_distribution(self) -> Dict[int, int]:
        if self.df.empty:
            logger.warning("No data for status code analysis")
            return {}
        
        try:
            counts = self.df['status'].value_counts().to_dict()
            logger.info(f"Found {len(counts)} status codes")
            return counts
        except Exception as e:
            logger.error(f"Error analyzing status codes: {e}")
            return {}

    def top_endpoints(self, n: int = 10) -> List[Tuple[str, int]]:
        if self.df.empty:
            logger.warning("No data for endpoint analysis")
            return []
        
        try:
            counts = self.df['path'].value_counts().head(n).to_dict()
            return list(counts.items())
        except Exception as e:
            logger.error(f"Error analyzing top endpoints: {e}")
            return []

    def request_volume_by_hour(self) -> Dict[int, int]:
        if self.df.empty:
            logger.warning("No data for hourly analysis")
            return {}
        
        try:
            # Add an 'hour' column derived from timestamps
            self.df['hour'] = self.df['timestamp'].apply(lambda x: x.hour)
            counts = self.df['hour'].value_counts().sort_index().to_dict()
            logger.info(f"Request volume analyzed across {len(counts)} hours")
            return counts
        except Exception as e:
            logger.error(f"Error analyzing hourly request volume: {e}")
            return {}

    def total_request_count(self) -> int:
        return len(self.entries)

    def average_response_size(self) -> float:
        if self.df.empty:
            logger.warning("No data for response size analysis")
            return 0.0
        
        try:
            avg = self.df['bytes_sent'].mean()
            logger.info(f"Average response size: {avg:.2f} bytes")
            return avg
        except Exception as e:
            logger.error(f"Error calculating average response size: {e}")
            return 0.0

    def http_method_distribution(self) -> Dict[str, int]:
        if self.df.empty:
            logger.warning("No data for HTTP method analysis")
            return {}
        
        try:
            counts = self.df['method'].value_counts().to_dict()
            logger.info(f"Found {len(counts)} HTTP methods")
            return counts
        except Exception as e:
            logger.error(f"Error analyzing HTTP methods: {e}")
            return {}

    def get_summary(self, top_n: int = 10) -> Dict[str, Any]:
        # Generate a summary dictionary with all metrics
        return {
            'total_requests': self.total_request_count(),
            'status_codes': self.status_code_distribution(),
            'top_endpoints': self.top_endpoints(top_n),
            'http_methods': self.http_method_distribution(),
            'hourly_request_volume': self.request_volume_by_hour(),
            'avg_response_size': self.average_response_size()
        }
