import subprocess
import re
import os
import sys
import csv
import xml.etree.ElementTree as ET

tomcat_dir = os.getenv('CATALINA_HOME')
def section1():
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
    def remove_extra_files():
        print("===Section 1.1===")
        webapps = ["examples", "docs", "ROOT", "host-manager", "manager"]

    # Loop through the webapps and check if they exist
        for webapp in webapps:
            path = os.path.join(tomcat_dir, "webapps", webapp)
            if os.path.exists(path):
                row = ['1.1 Remove extraneous files and directories', path + 'exist', 'No', 'rm -rf $CATALINA_HOME/webapps/docs \ $CATALINA_HOME/webapps/examples \ $CATALINA_HOME/webapps/ROOT']
            csv_output(row)

    def disable_unused_connectors():
        print("===Section 1.2===")
        required_connectors = ["HTTP/1.1"] # Replace with the actual required Connectors

    # Find all Connectors in the server.xml file
        cmd = f'grep "Connector" {tomcat_dir}/conf/server.xml'
        output = os.popen(cmd).read()
        
        # Split the output into individual lines and loop through them
        for line in output.splitlines():
            # Check if the line contains one of the required Connectors
            if any(connector in line for connector in required_connectors):
                # Check if the line is commented out
                if line.startswith("<!--") and line.endswith("-->"):
                    row = ['1.2 Disable Unused Connectors', line + 'is required but commented out', 'No', 'Add or uncomment required connectors']
                    csv_output(row)
            else:
                # Check if the line is commented out
                if not line.startswith("<!--") or not line.endswith("-->"):
                    row = ['1.2 Disable Unused Connectors', line + 'is not required but in used', 'No', 'Remove or uncomment required connectors']
                    csv_output(row)
    remove_extra_files()
    disable_unused_connectors()