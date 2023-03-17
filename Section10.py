import csv
import os
import re
import subprocess
import sys
import pathlib

def csv_output(row):
    header_row = ['Control Check', 'Current Setting', 'Audit Finding', 'Remediation']
    if not os.path.exists('output.csv'):
        # If the file does not exist, create a new file with the header row
        with open('output.csv', mode='w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(header_row)
            writer.writerow(row)
    else:
        # If the file exists, check if it has a header row
        with open('output.csv', mode='r') as csv_file:
            reader = csv.reader(csv_file)
            header_row = next(reader, [])
            if header_row != header_row:
                # If the file does not have a header row, add it
                with open('output.csv', mode='w', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    writer.writerow(header_row)
                    writer.writerow(row)
            else:
                # If the file has a header row, find the next empty row to write the new data
                with open('output.csv', mode='a', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    found_empty_row = False
                    while not found_empty_row:
                        try:
                            next_row = next(reader)
                            if not any(next_row):
                                writer.writerow(row)
                                found_empty_row = True
                        except StopIteration:
                            writer.writerow(row)
                            found_empty_row = True

def section10(csvFile):
    apache_conf_file  = os.getenv('CATALINA_HOME/conf/')
    control_check = 'Verify Limit Request Configuration'
    header_row = [control_check, 'Current Setting', 'Audit Finding', 'Remediation']
    rows = [header_row]

    expected_values = ["512", "100", "1024", "102400"]
    search_reg_exp = [r"^512$", r"^100$", r"^1024$", r"^102400$"]
    directive_lines = ["LimitRequestLine 512", "LimitRequestFields 100", "LimitRequestFieldSize 1024",
                       "LimitRequestBody 102400"]
    directives = ["LimitRequestLine", "LimitRequestFields", "LimitRequestFieldSize", "LimitRequestBody"]
    found = [False, False, False, False]
    changed = [False, False, False, False]
    issues = []

    if os.path.exists('conf{}'.format(apache_conf_file)):
        apache_conf_file = 'conf{}'.format(apache_conf_file)

    apacheConfSplit = open(apache_conf_file).read().split('\n')

    for index in range(len(apacheConfSplit)):
        for i in range(0, 4):
            # If directive is in current line
            if directives[i] in apacheConfSplit[index]:
                limit_req_line = apacheConfSplit[index].split()
                original_value = limit_req_line[1]

                # Don't change the original value if it's correct.
                if re.match(search_reg_exp[i], original_value):
                    found[i] = True
                    current_setting = original_value
                    audit_finding = 'Pass'
                    remediation = 'N/A'
                    row = [control_check, current_setting, audit_finding, remediation]
                    rows.append(row)

                # Change the original value if it's incorrect.
                else:
                    changed[i] = True
                    current_setting = original_value
                    audit_finding = 'Fail'
                    remediation = 'echo "{}" >> {}'.format(directive_lines[i], apache_conf_file)
                    row = [control_check, current_setting, audit_finding, remediation]
                    rows.append(row)

    for j, found_bool in enumerate(found):
        if not found_bool and not changed[j]:
            # If directive doesn't exist in config, write to csv file
            current_setting = 'N/A'
            audit_finding = 'Fail'
            remediation = 'echo "{}" >> {}'.format(directive_lines[j], apache_conf_file)
            issue = directives[j] + " is missing from the configuration file"
            row = [control_check, current_setting, audit_finding, remediation]
            rows.append(row)

    with open(csvFile, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(rows)