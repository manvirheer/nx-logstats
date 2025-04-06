"""
Reporter module for nx-logstats

This module handles the formatting and output of log analysis results.
It supports different output formats and destinations.
"""

import json
import logging
from typing import Dict, Any, Optional, TextIO
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Set up logger
logger = logging.getLogger(__name__)
console = Console()

class Reporter:
    """
    Formats and outputs analysis results.
    Supports text and JSON formats with Rich library for enhanced 
    terminal visualization.
    """
    
    def __init__(self, summary: Dict[str, Any]):
        self.summary = summary
        
    def generate_text_report(self) -> str:
        # Generate a human-readable text report using Rich formatting
        try:
            report = []
            
            # Use Rich to generate prettier tables and panels
            title = Text("NGINX ACCESS LOG ANALYSIS REPORT", style="bold white on blue")
            subtitle = Text(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # General stats panel
            general_stats = f"Total Requests: {self.summary['total_requests']}\n"
            avg_size = self.summary.get('avg_response_size', 0)
            general_stats += f"Average Response Size: {avg_size:.2f} bytes"
            
            # Status codes table
            status_table = Table(title="HTTP Status Code Distribution")
            status_table.add_column("Status", style="cyan")
            status_table.add_column("Count", style="magenta")
            status_table.add_column("Percentage", style="green")
            
            status_codes = self.summary.get('status_codes', {})
            if status_codes:
                for status, count in sorted(status_codes.items()):
                    percentage = f"{count/self.summary['total_requests']*100:.1f}%"
                    status_table.add_row(str(status), str(count), percentage)
            else:
                status_table.add_row("No data", "-", "-")
                
            # HTTP methods table
            method_table = Table(title="HTTP Method Distribution")
            method_table.add_column("Method", style="cyan")
            method_table.add_column("Count", style="magenta")
            method_table.add_column("Percentage", style="green")
            
            methods = self.summary.get('http_methods', {})
            if methods:
                for method, count in sorted(methods.items(), key=lambda x: x[1], reverse=True):
                    percentage = f"{count/self.summary['total_requests']*100:.1f}%"
                    method_table.add_row(method, str(count), percentage)
            else:
                method_table.add_row("No data", "-", "-")
                
            # Top endpoints table
            endpoint_table = Table(title="Top Requested Endpoints")
            endpoint_table.add_column("Rank", style="cyan")
            endpoint_table.add_column("Endpoint", style="blue")
            endpoint_table.add_column("Count", style="magenta")
            endpoint_table.add_column("Percentage", style="green")
            
            endpoints = self.summary.get('top_endpoints', [])
            if endpoints:
                for i, (endpoint, count) in enumerate(endpoints, 1):
                    percentage = f"{count/self.summary['total_requests']*100:.1f}%"
                    endpoint_table.add_row(str(i), endpoint, str(count), percentage)
            else:
                endpoint_table.add_row("-", "No data", "-", "-")
                
            # Hourly distribution table
            hourly_table = Table(title="Request Volume by Hour")
            hourly_table.add_column("Hour", style="cyan")
            hourly_table.add_column("Count", style="magenta")
            
            hourly = self.summary.get('hourly_request_volume', {})
            if hourly:
                for hour in sorted(hourly.keys()):
                    count = hourly[hour]
                    hourly_table.add_row(f"{hour:02d}:00 - {hour:02d}:59", str(count))
            else:
                hourly_table.add_row("No data", "-")
            
            # Generate the rich console output as a string
            str_io = console.capture()
            console.print(Panel(title, subtitle=subtitle))
            console.print(Panel(general_stats, title="General Statistics"))
            console.print(status_table)
            console.print(method_table)
            console.print(endpoint_table)
            console.print(hourly_table)
            console.print(Panel("END OF REPORT"))
            output = str_io.get()
            
            return output
            
        except Exception as e:
            logger.error(f"Error generating text report: {e}")
            return f"Error generating report: {e}"
            
    def generate_json_report(self) -> str:
        # Generate a JSON-formatted report
        try:
            # Add timestamp to the report
            report_data = {
                "generated_at": datetime.now().isoformat(),
                "metrics": self.summary
            }
            return json.dumps(report_data, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            return json.dumps({"error": str(e)})
            
    def output_to_file(self, filepath: str, format: str = "text") -> bool:
        # Write the report to a file
        try:
            with open(filepath, 'w') as f:
                if format.lower() == 'json':
                    f.write(self.generate_json_report())
                else:
                    f.write(self.generate_text_report())
            logger.info(f"Report successfully written to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error writing report to file {filepath}: {e}")
            return False
            
    def print_to_console(self, format: str = "text") -> None:
        # Print the report to the console using Rich when appropriate
        try:
            if format.lower() == 'json':
                # For JSON, use Rich's syntax highlighting
                json_data = self.generate_json_report()
                console.print_json(json_data)
            else:
                # Rich formatted report is already prepared by generate_text_report
                # We're just printing the captured output
                print(self.generate_text_report())
        except Exception as e:
            logger.error(f"Error printing report to console: {e}")
            console.print(f"[bold red]Error generating report:[/] {e}")