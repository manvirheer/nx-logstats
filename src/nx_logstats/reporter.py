"""
Reporter module for nx-logstats

This module handles the formatting and output of log analysis results.
It supports different output formats and destinations.
"""

import json
import logging
from typing import Dict, Any
from datetime import datetime

from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns

# Set up logger
# TODO: For Future, we can add a custom formatter to the logger to include timestamps and other details. Also, give an option to output to a file.
logger = logging.getLogger(__name__)
console = Console()


def format_timestamp(dt: datetime) -> str:
    # Format the timestamp with full month name.
    return dt.strftime("%Y-%B-%d %H:%M:%S")


def color_for_status(status: int) -> str:
    # Return a color based on the status code category.
    if 200 <= status < 300:
        return "green"
    elif 300 <= status < 400:
        return "blue"
    elif 400 <= status < 500:
        return "yellow"
    elif 500 <= status < 600:
        return "red"
    return "white"


class Reporter:
    """
    Formats and outputs analysis results.
    Supports text and JSON formats with Rich library for enhanced 
    terminal visualization.
    """
    
    def __init__(self, summary: Dict[str, Any]):
        self.summary = summary

    def _build_general_stats_table(self) -> Table:
        table = Table(show_header=False, box=None)
        table.add_column("Label")
        table.add_column("Value")
        table.add_row("Total Requests:", f"{self.summary['total_requests']}")
        table.add_row("Average Response Size:", f"{self.summary.get('avg_response_size', 0):.2f} bytes")
        
        # Add a row for ignored lines if present.
        if self.summary.get("ignored_lines", 0) > 0:
            table.add_row("[bold red]Ignored Lines[/]", f"[bold red]{self.summary['ignored_lines']}[/]")
        
        table.add_row("Generated at:", f"{format_timestamp(datetime.now())}")
        return table

    def _build_status_table(self) -> Table:
        table = Table(title="HTTP Status Code Distribution", border_style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Count", justify="right")
        table.add_column("Percentage", justify="right")
        status_codes = self.summary.get('status_codes', {})
        if status_codes:
            for status, count in sorted(status_codes.items()):
                try:
                    status_int = int(status)
                except ValueError:
                    status_int = 0
                status_color = color_for_status(status_int)
                colored_status = f"[{status_color}]{status}[/]"
                percentage = f"{count/self.summary['total_requests']*100:.1f}%"
                table.add_row(colored_status, str(count), percentage)
        else:
            table.add_row("No data", "-", "-")
        return table

    def _build_http_methods_table(self) -> Table:
        table = Table(title="HTTP Method Distribution", border_style="dim")
        table.add_column("Method", justify="center")
        table.add_column("Count", justify="right")
        table.add_column("Percentage", justify="right")
        methods = self.summary.get('http_methods', {})
        if methods:
            for method, count in sorted(methods.items(), key=lambda x: x[1], reverse=True):
                percentage = f"{count/self.summary['total_requests']*100:.1f}%"
                table.add_row(method, str(count), percentage)
        else:
            table.add_row("No data", "-", "-")
        return table

    def _build_top_endpoints_table(self) -> Table:
        table = Table(title="Top Requested Endpoints", border_style="dim")
        table.add_column("Rank", justify="center")
        table.add_column("Endpoint")
        table.add_column("Count", justify="right")
        table.add_column("Percentage", justify="right")
        endpoints = self.summary.get('top_endpoints', [])
        if endpoints:
            for i, (endpoint, count) in enumerate(endpoints, 1):
                percentage = f"{count/self.summary['total_requests']*100:.1f}%"
                rank_str = f"[bold green]{i}[/]" if i == 1 else f"[dim]{i}[/]"
                table.add_row(rank_str, endpoint, str(count), percentage)
        else:
            table.add_row("-", "No data", "-", "-")
        return table

    def _build_hourly_table(self) -> Table:
        table = Table(title="Request Volume by Hour", border_style="dim")
        table.add_column("Hour", justify="center")
        table.add_column("Count", justify="right")
        hourly = self.summary.get('hourly_request_volume', {})
        if hourly:
            for hour in sorted(hourly.keys()):
                count = hourly[hour]
                table.add_row(f"{hour:02d}:00 - {hour:02d}:59", str(count))
        else:
            table.add_row("No data", "-")
        return table

    def _build_report_panel(self) -> Panel:
        # Assemble all components into a single panel.
        general_stats = self._build_general_stats_table()
        status_table = self._build_status_table()
        method_table = self._build_http_methods_table()
        endpoints_table = self._build_top_endpoints_table()
        hourly_table = self._build_hourly_table()
        
        stats_panel = Panel(general_stats, title="General Statistics", border_style="blue")
        tables_row1 = Columns([status_table, method_table])
        tables_row2 = Columns([hourly_table, endpoints_table])
        report_group = Group(stats_panel, tables_row1, tables_row2)
        report_title = "NGINX ACCESS LOG ANALYSIS REPORT"
        return Panel(report_group, title=report_title, border_style="blue", title_align="center")

    def generate_text_report(self) -> str:
        # Generate a human-readable text report using Rich formatting.
        # TODO: Add ability to create graphs for distributions.
        try:
            from io import StringIO
            from contextlib import redirect_stdout

            output = StringIO()
            with redirect_stdout(output):
                local_console = Console(file=output, width=100)
                title = Text("NGINX ACCESS LOG ANALYSIS REPORT", style="bold blue")
                subtitle = Text(f"Generated at: {format_timestamp(datetime.now())}")
                local_console.print(Panel(title, subtitle=subtitle, border_style="blue"))
                local_console.print(self._build_report_panel())
                local_console.print(Panel("END OF REPORT", border_style="dim"))
            return output.getvalue()
        except Exception as e:
            logger.error(f"Error generating text report: {e}")
            return f"Error generating report: {e}"

    def generate_json_report(self) -> str:
        # Generate a JSON-formatted report.
        try:
            report_data = {
                "generated_at": format_timestamp(datetime.now()),
                "metrics": self.summary
            }
            return json.dumps(report_data, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            return json.dumps({"error": str(e)})

    def output_to_file(self, filepath: str, format: str = "text") -> bool:
        # Write the report to a file.
        try:
            with open(filepath, 'w') as f:
                if format.lower() == 'json':
                    f.write(self.generate_json_report())
                else:
                    f.write(self.generate_text_report())
            logger.debug(f"Report successfully written to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error writing report to file {filepath}: {e}")
            return False

    def print_to_console(self, format: str = "text") -> None:
        # Print the report to the console.
        try:
            if format.lower() == 'json':
                console.print_json(self.generate_json_report())
            else:
                console.print(self._build_report_panel())
        except Exception as e:
            logger.error(f"Error printing report to console: {e}")
            console.print(f"[bold red]Error generating report:[/] {e}")
