import csv
import os
from csvoutput import csv_output


def section8():
    print('====Start of section 8====')
    print('Restrict runtime access to sensitive packages\n')
    control_check = '8.1 Restrict runtime access to sensitive packages'
    header_row = [control_check, 'Current Setting', 'Audit Finding', 'Remediation']
    rows = [header_row]
    catalina_properties = os.getenv('CATALINA_HOME/conf/catalina.properties')
    with open(catalina_properties , 'r') as f:
        for line in f:
            if line.startswith('package.access'):
                packages = line.split('=')[1].strip().split(',')
                print(packages)

    current_setting = 'Packages that are allowed: ' + packages
    audit_finding = 'N/A'
    remediation = 'Please ensure that these packages are not unknown as unknown packages may be malicious or dangerous to the application'

    row = [control_check, current_setting, audit_finding, remediation]
    rows.append(row)
    csv_output(rows)
    print('====End of section 8====')