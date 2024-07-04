#!/usr/bin/env python3

import re
import os
import glob
from datetime import datetime, timedelta
from collections import defaultdict

# Path to the audit log files
audit_log_dir = '/var/log/audit/'
log_files_pattern = os.path.join(audit_log_dir, 'audit.log*')

# Get current time and time 24 hours ago
now = datetime.now()
time_24_hours_ago = now - timedelta(days=1)

# Find all log files modified in the last 24 hours
log_files = [f for f in glob.glob(log_files_pattern) if datetime.fromtimestamp(os.path.getmtime(f)) > time_24_hours_ago]

# Regular expression to extract timestamp and key
audit_regex = re.compile(r'type=.* msg=audit\((\d+)\.\d+:\d+\):.* key="([^"]*)"')

# Dictionary to store the count of keys per hour
key_counts_per_hour = defaultdict(lambda: defaultdict(int))

# Read the audit log files
for log_file in log_files:
    print(f"Processing file: {log_file}")
    with open(log_file, 'r') as file:
        for line in file:
            match = audit_regex.search(line)
            if match:
                timestamp = float(match.group(1))
                key = match.group(2)
                # Convert timestamp to hour of the day
                dt_object = datetime.fromtimestamp(timestamp)
                hour = dt_object.hour
                # Increment the count for the key in the specific hour
                key_counts_per_hour[hour][key] += 1

# Create a list of hours
hours = list(range(24))

# Gather all unique keys
all_keys = set()
for hour in hours:
    all_keys.update(key_counts_per_hour[hour].keys())

# Sort the keys
all_keys = sorted(all_keys)

# Define the column width
key_col_width = 40
hour_col_width = 10

# Print the header
header = f"{'Key':<{key_col_width}}" + "".join(f"{hour:02d}".center(hour_col_width) for hour in hours)
print(header)
print('-' * len(header))

# Initialize a dictionary to keep track of total counts per hour
total_counts_per_hour = {hour: 0 for hour in hours}

# Print the counts for each key
for key in all_keys:
    row = f"{key:<{key_col_width}}" + "".join(f"{key_counts_per_hour[hour].get(key, 0):<{hour_col_width}}" for hour in hours)
    print(row)
    # Update the total counts
    for hour in hours:
        total_counts_per_hour[hour] += key_counts_per_hour[hour].get(key, 0)

# Print the total row
total_row = f"{'Total':<{key_col_width}}" + "".join(f"{total_counts_per_hour[hour]:<{hour_col_width}}" for hour in hours)
print('-' * len(header))
print(total_row)
