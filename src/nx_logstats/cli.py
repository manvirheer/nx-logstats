"""
Command-line interface module for nx-logstats

This module provides the command-line interface for the nx-logstats tool,
handling argument parsing and program execution.
"""

import argparse
import logging
import sys
from datetime import datetime
from typing import List, Optional

from rich.logging import RichHandler

from nx_logstats.parser import parse_log_file, is_likely_nginx_log
from nx_logstats.analysis import LogAnalyzer
from nx_logstats.reporter import Reporter

def configure_logging(verbose: bool = False) -> None:
    # Configure logging level and format with Rich formatting
    log_level = logging.DEBUG if verbose else logging.INFO
    # Use Rich for prettier logging output
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )

def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="NGINX log file analyzer - extracts and reports on key metrics",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "logfile",
        help="Path to the NGINX access log file to analyze"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Path to write the output report (default: print to stdout)",
        default=None
    )
    
    parser.add_argument(
        "-f", "--format",
        help="Output format (text or json)",
        choices=["text", "json"],
        default="text"
    )
    
    parser.add_argument(
        "-n", "--top-n",
        help="Number of top endpoints to include in the report",
        type=int,
        default=10
    )
    
    parser.add_argument(
        "-v", "--verbose",
        help="Enable verbose output",
        action="store_true"
    )
    
    parser.add_argument(
        "--ignore-errors",
        help="Ignore malformed log lines and continue processing",
        action="store_true"
    )
    
    return parser.parse_args(args)

def main(args: Optional[List[str]] = None) -> int:
    # Main entry point for the CLI
    parsed_args = parse_args(args)
    configure_logging(parsed_args.verbose)
    
    logger = logging.getLogger(__name__)
    logger.info(f"Starting analysis of {parsed_args.logfile}")
    
    try:
        # Check if file is likely an NGINX log
        if not is_likely_nginx_log(parsed_args.logfile):
            logger.warning(f"File {parsed_args.logfile} does not appear to be an NGINX log file.")
            logger.warning("Note: This tool only supports standard NGINX access log format")
            
        # Parse log file
        log_entries, error_count = parse_log_file(parsed_args.logfile, 
                                                 ignore_errors=parsed_args.ignore_errors)
        
        if not log_entries:
            logger.error("No valid log entries found in the log file")
            if error_count > 0:
                logger.error(f"{error_count} lines were malformed or unrecognized")
                logger.error("Try using --ignore-errors to suppress these warnings")
            return 1
            
        logger.info(f"Successfully parsed {len(log_entries)} log entries")
        if error_count > 0:
            logger.warning(f"Skipped {error_count} invalid entries during parsing")
        
        # Analyze log entries
        analyzer = LogAnalyzer(log_entries)
        summary = analyzer.get_summary(top_n=parsed_args.top_n)
        
        # Generate and output report
        reporter = Reporter(summary)
        
        if parsed_args.output:
            success = reporter.output_to_file(parsed_args.output, parsed_args.format)
            if not success:
                return 1
            logger.info(f"Report written to {parsed_args.output}")
        else:
            reporter.print_to_console(parsed_args.format)
            
        logger.info("Analysis completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Error during execution: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())