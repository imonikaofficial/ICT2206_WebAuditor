import subprocess
import re
import os
import sys
import csv
import xml.etree.ElementTree as ET

tomcat_dir = os.getenv('CATALINA_HOME')
def section5():
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
    def use_secure_realm():
        print("===Section 5.1===")
        realms = ["MemoryRealm", "JDBCRealm", "UserDatabaseRealm", "JAASRealm"]

    # Loop through the realms and check if they're present in the server.xml file
        for realm in realms:
            cmd = f'grep "Realm className" {tomcat_dir}/conf/server.xml | grep {realm}'
            output = os.popen(cmd).read()
            if output:
                row = ['5.1 Use secure Realms', realm + ' was used', 'No', 'Set to the one of the appropriate realms']
                csv_output(row)
    use_secure_realm()
    def use_lockout_realm():
        print("===Section 5.2===")
        cmd = f'grep "LockOutRealm" {tomcat_dir}/conf/server.xml'
        output = os.popen(cmd).read()
        if output:
            row = ['5.2 Use lockout Realms', 'LockOut was used', 'No', 'Do the following: <Realm className="org.apache.catalina.realm.LockOutRealm" failureCount="3" lockOutTime="600" cacheSize="1000" cacheRemovalWarningTime="3600">']
            csv_output(row)
    use_lockout_realm()