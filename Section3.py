import subprocess
import re
import os
import sys
import csv
import xml.etree.ElementTree as ET

tomcat_dir = os.getenv('CATALINA_HOME')
def section3():
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

    def nondeterministic_shutdown_command():
        print("===Section 3.1===")

    # Define the path to server.xml file
        server_xml_path = os.path.join(tomcat_dir, 'conf', 'server.xml')
        
        # Define the regular expression to check if the shutdown attribute is set to "SHUTDOWN"
        shutdown_regex = r'shutdown\s*=\s*"SHUTDOWN"'
        
        # Search for the regular expression in the server.xml file
        with open(server_xml_path, 'r') as f:
            contents = f.read()
            if re.search(shutdown_regex, contents):
                row = ['3.1 Set a nondeterministic Shutdown command value', 'The shutdown attribute in ' + server_xml_path + ' is set to SHUTDOWN', 'No', 'shutdown="NONDETERMINISTICVALUE"']
                csv_output(row)
            else:
                print('Correctly set')
    nondeterministic_shutdown_command()
    def disable_shutdown_port():
        print("===Section 3.2===")

    # Define the path to server.xml file
        server_xml_path = os.path.join(tomcat_dir, 'conf', 'server.xml')
        
        # Define the regular expression to check if the port attribute is set to -1
        port_regex = r'<Server\s+[^>]*port\s*=\s*"-1"'
        
        # Search for the regular expression in the server.xml file
        with open(server_xml_path, 'r') as f:
            contents = f.read()
            if re.search(port_regex, contents):
                row = ['3.2 Disable the Shutdown port', 'The shutdown port attribute in ' + server_xml_path + ' is set to a revealing port', 'No', 'Server port="-1"']
                csv_output(row)
            else:
                print('Correctly set')
    disable_shutdown_port()