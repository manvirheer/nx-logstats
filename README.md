# nx-logstats: NGINX Log Analysis Tool

A NGINX log analysis tool that parses a given log file (e.g., NGINX access logs), summarizes key metrics such as request volume, status code distribution, frequently accessed endpoints, outputs a clean report and number of requests per hour of the day to showcase the temporal traffic patterns. 

## Overview

`nx-logstats` is a command-line utility that parses NGINX access logs, calculates key metrics, and presents them in a readable format. It's designed to be straightforward to use while providing meaningful insights from your server logs. Output can be in JSON or simple text. It can be shown in the terminal or stored in a file such as `results.json`.

Key features:
- Parse standard NGINX access log formats
- Extract multiple metrics from log data:
  - HTTP status code distribution
  - Most frequently accessed endpoints
  - Request volume by hour
  - HTTP method distribution
  - Average response size
- Output to terminal or file in text or JSON formats
- Robust error handling for malformed log entries
- Different Logging levels that can be configured with options -v for info level logs and -vv for debug level logs.
- Configured with Github Workflow which publishes the artifact to PyPi repository so that it can be accessed by anyone globally, available at https://pypi.org/project/nx-logstats/ and https://github.com/manvirheer/nx-logstats/actions. 

## Installation

### From PyPI (Not suitable for running tests but packaged for production usage)

```bash
pip install nx-logstats
```

### From Source (Preferred for running tests)

```bash
git clone https://github.com/manvirheer/nx-logstats.git
cd nx-logstats
```

### Suggestion - Create a Virtual Environment 
For Windows 
```bash
python -m venv venv
venv\Scripts\activate
```
For Linux/MacOS
```bash
python -m venv venv
source venv/bin/activate
```

For development and testing:

```bash
pip install -e ".[dev]"
```

## Usage

### Basic usage:
There is a sample_logs/ folder available in the repository which can be used to test the solution.

```bash
nx-logstats ./sample_logs/valid_simple_logs.txt
nx-logstats ./sample_logs/errors_small_dataset.txt
nx-logstats ./sample_logs/errors_small_dataset.txt --ignore-errors
nx-logstats ./sample_logs/errors_small_dataset.txt --ignore-errors -f json -o results.json
nx-logstats ./sample_logs/errors_small_dataset.txt -v
nx-logstats ./sample_logs/errors_small_dataset.txt -vv
```

### Command Line Options

```
usage: nx-logstats [-h] [-o OUTPUT] [-f {text,json}] [-n TOP_N] [-v] [--ignore-errors] logfile

NGINX log file analyzer - extracts and reports on key metrics. Accepted format is: <ip> - - [<dd/Mon/YYYY:HH:MM:SS>] "<HTTP_METHOD> <path> HTTP/1.1" <status> <bytes>

positional arguments:
  logfile               Path to the NGINX access log file to analyze

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Path to write the output report (default: print to stdout)
  -f {text,json}, --format {text,json}
                        Output format (text or json) (default: text)
  -n TOP_N, --top-n TOP_N
                        Number of top endpoints to include in the report (default: 10)
  -v, --verbose         Increase verbosity: -v for INFO, -vv for DEBUG. Default shows only errors. (default: 0)
  --ignore-errors       Ignore malformed log lines and continue processing (default: False)
```

### Sample Output

When using the text format, the output will look similar to:

```
┌─────────────────────── NGINX ACCESS LOG ANALYSIS REPORT ───────────────────────┐
└──────────────────── Generated at: 2025-April-06 12:34:56 ────────────────────┘
┌─────────────────────────── General Statistics ───────────────────────────┐
│ Total Requests:       1242                                               │
│ Average Response Size: 4231.76 bytes                                     │
│ Generated at:         2025-April-06 12:34:56                             │
└────────────────────────────────────────────────────────────────────────┘
┌─── HTTP Status Code Distribution ────┐  ┌───── HTTP Method Distribution ─────┐
│ Status │ Count    │ Percentage       │  │ Method │ Count    │ Percentage     │
│ 200    │ 1024     │ 82.4%            │  │ GET    │ 985      │ 79.3%          │
│ 404    │ 156      │ 12.6%            │  │ POST   │ 192      │ 15.5%          │
│ 500    │ 42       │ 3.4%             │  │ PUT    │ 38       │ 3.1%           │
│ 302    │ 20       │ 1.6%             │  │ DELETE │ 27       │ 2.2%           │
└──────────────────────────────────────┘  └────────────────────────────────────┘

...
...
...
```

## Running Tests

Run the test suite with:

```bash
pytest
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

#### Design Considerations
For the design considerations, review the Design.md