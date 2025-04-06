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

from nx_logstats.parser import LogParser
from nx_logstats.analysis import LogAnalyzer
from nx_logstats.reporter import Reporter

# Define a list of CLI option definitions.
CLI_OPTIONS = [
    {
        "flags": ["logfile"],
        "params": {
            "help": "Path to the NGINX access log file to analyze"
        }
    },
    {
        "flags": ["-o", "--output"],
        "params": {
            "help": "Path to write the output report (default: print to stdout)",
            "default": None
        }
    },
    {
        "flags": ["-f", "--format"],
        "params": {
            "help": "Output format (text or json)",
            "choices": ["text", "json"],
            "default": "text"
        }
    },
    {
        "flags": ["-n", "--top-n"],
        "params": {
            "help": "Number of top endpoints to include in the report",
            "type": int,
            "default": 10
        }
    },
    {
        "flags": ["-v", "--verbose"],
        "params": {
            "help": "Increase verbosity: -v for INFO, -vv for DEBUG. Default shows only errors.",
            "action": "count",
            "default": 0
        }
    },
    {
        "flags": ["--ignore-errors"],
        "params": {
            "help": "Ignore malformed log lines and continue processing",
            "action": "store_true"
        }
    }
]

def configure_logging(verbosity: int = 0) -> None:
    # Set logging level based on verbosity flag:
    # 0: errors only; 1: info and above; 2 or more: debug and above.
    if verbosity >= 2:
        log_level = logging.DEBUG
    elif verbosity == 1:
        log_level = logging.INFO
    else:
        log_level = logging.ERROR

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )

def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    # Parse command-line arguments using the CLI_OPTIONS mapping.
    parser = argparse.ArgumentParser(
        description="NGINX log file analyzer - extracts and reports on key metrics",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    for option in CLI_OPTIONS:
        parser.add_argument(*option["flags"], **option["params"])
    
    return parser.parse_args(args)

def main(args: Optional[List[str]] = None) -> int:
    parsed_args = parse_args(args)
    configure_logging(parsed_args.verbose)
    
    logger = logging.getLogger(__name__)
    logger.info(f"Starting analysis of {parsed_args.logfile}")
    
    try:
        parser_instance = LogParser(parsed_args.logfile, ignore_errors=parsed_args.ignore_errors)
        if not parser_instance.is_likely_nginx_log():
            logger.warning(f"File {parsed_args.logfile} does not appear to be an NGINX log file.")
            logger.warning("Note: This tool only supports standard NGINX access log format")
            
        log_entries, error_count = parser_instance.parse()
        
        # Abort if there were malformed lines and ignore_errors is False
        if error_count > 0 and not parsed_args.ignore_errors:
            logger.error(f"Encountered {error_count} malformed lines while processing. Aborting.")
            logging.error("Use --ignore-errors to skip malformed lines.")
            return 1
            
        if not log_entries:
            logger.error("No valid log entries found in the log file")
            if error_count > 0:
                logger.error(f"{error_count} lines were malformed or unrecognized")
                logger.error("Try using --ignore-errors to suppress these warnings")
            return 1
            
        logger.info(f"Successfully parsed {len(log_entries)} log entries")
        if error_count > 0:
            logger.warning(f"Skipped {error_count} invalid entries during parsing")
        
        analyzer = LogAnalyzer(log_entries)
        summary = analyzer.get_summary(top_n=parsed_args.top_n)
        
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
