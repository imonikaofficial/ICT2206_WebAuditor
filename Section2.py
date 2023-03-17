import subprocess
import re
import os
import sys
import csv
import xml.etree.ElementTree as ET

tomcat_dir = os.getenv('CATALINA_HOME')
def section2():
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
  def alter_server_info():
      print("===Section 2.1===")

      # Build the command to list the contents of the /opt/tomcat directory
      cd_cmd = "cd " + tomcat_dir + "/lib"
      jar_cmd = "jar xf catalina.jar org/apache/catalina/util/ServerInfo.properties"

      # Build the command to search for the server.info property in the ServerInfo.properties file
      grep_cmd = "grep server.info org/apache/catalina/util/ServerInfo.properties"

      # Combine the commands into a single command to be executed by subprocess
      full_cmd = f"{cd_cmd}; {jar_cmd}; {grep_cmd}"

      # Execute the combined command using subprocess.run() and print the output
      grep_output = subprocess.run(full_cmd, shell=True, check=True, capture_output=True, text=True)
      server_info = grep_output.stdout.strip()
      pattern = r"server.info=Apache Tomcat/\d+.\d+.\d+"

      # Use the search() method of the re module to search for a match in the text
      match = re.search(pattern, server_info)
      remedy_needed = False

      # Check if a match was found
      if not match:
          print("Good! No name of the application service is found.")
          remedy_needed = False
      else:
          # Define the row data for the CSV file	
          row = ['2.1 Alter the Advertised server.info String', server_info, 'No', 'server.info=Tomcat']
          csv_output(row)
          remedy_needed = True
  alter_server_info()

  def alter_tomcat_server_number():
      print("===Section 2.2===")
      # Build the command to list the contents of the /opt/tomcat directory
      cd_cmd = "cd " + tomcat_dir + "/lib"

      jar_cmd = "jar xf catalina.jar org/apache/catalina/util/ServerInfo.properties"

      # Build the command to search for the server.number property in the ServerInfo.properties file
      grep_cmd = "grep server.number org/apache/catalina/util/ServerInfo.properties"

      # Combine the commands into a single command to be executed by subprocess
      full_cmd = f"{cd_cmd}; {jar_cmd}; {grep_cmd}"

      # Execute the combined command using subprocess.run() and print the output
      grep_output = subprocess.run(full_cmd, shell=True, check=True, capture_output=True, text=True)
      ver_info = grep_output.stdout.strip()
      pattern = r"server\.number=\d+(\.\d+)*"

      # Use the search() method of the re module to search for a match in the text
      match = re.search(pattern, ver_info)
      remedy_needed = False
      # Check if a match was found
      if not match:
          print("Good! No version of the application service is found.")
          remedy_needed = False
      else:
          row = ['2.2 Alter the Advertised server.number String', ver_info, 'No', 'server.number=hidden']
          csv_output(row)
          remedy_needed = True
  alter_tomcat_server_number()

  def alter_tomcat_server_built():
      print("===Section 2.3===")

      # Build the command to list the contents of the /opt/tomcat directory
      cd_cmd = "cd " + tomcat_dir + "/lib"

      jar_cmd = "jar xf catalina.jar org/apache/catalina/util/ServerInfo.properties"

      # Build the command to search for the server.info property in the ServerInfo.properties file
      grep_cmd = "grep server.built org/apache/catalina/util/ServerInfo.properties"

      # Combine the commands into a single command to be executed by subprocess
      full_cmd = f"{cd_cmd}; {jar_cmd}; {grep_cmd}"

      # Execute the combined command using subprocess.run() and print the output
      grep_output = subprocess.run(full_cmd, shell=True, check=True, capture_output=True, text=True)
      built_info = grep_output.stdout.strip()
      pattern = r"server\.built=\w{3} \d{1,2} \d{4} \d{1,2}:\d{2}:\d{2}(:\w{3})?"

      # Use the search() method of the re module to search for a match in the text
      match = re.search(pattern, built_info)
      remedy_needed = False

      # Check if a match was found
      if not match:
          print("Good! No built application service is found.")
          remedy_needed = False
      else:
          row = ['2.3 Alter the Advertised server.built String', built_info, 'No', 'server.built=hidden']
          csv_output(row)
          remedy_needed = True
  alter_tomcat_server_built()
  def disable_xpoweredby():
      print("===Section 2.4===")

      # Define the server.xml file path
      server_xml_path = os.path.join(tomcat_dir, 'conf', 'server.xml')

      # Parse the server.xml file
      tree = ET.parse(server_xml_path)
      root = tree.getroot()

      # Loop through all Connector elements in the server.xml file
      for connector in root.findall('.//Connector'):

          # Check if the Connector has the xpoweredBy attribute
          if 'xpoweredBy' in connector.attrib:

              # Check if the xpoweredBy attribute is set to true
              if connector.attrib['xpoweredBy'].lower() == 'true':
                  row = ['2.4 Disable X-Powered-By HTTP Header and Rename the Server Value for all Connectors', 'xpoweredBy in ' + server_xml_path + ' is set to true', 'No', 'xpoweredBy="false"']
                  csv_output(row)
              else:
                  print("xpoweredBy is already set to False")
          else:
              print("No remedy needed")

      # Write the modified server.xml file
      tree.write(server_xml_path)
      print("Done")
  disable_xpoweredby()

  def disable_client_facing_stack_traces():
    print("===Section 2.5===")

    web_xml_path = os.path.join(tomcat_dir, 'conf', 'web.xml')

  # Load the web.xml file into an ElementTree object
    tree = ET.parse(web_xml_path)
    root = tree.getroot()

  # Check if an error-page element is defined
    error_page = root.find('error-page')
    if error_page is None:
        row = ['2.5 Disable client facing Stack Traces', 'error-page not found', 'No', 'Add error-page element in web.xml']
        csv_output(row)
    else:
      # If an error-page element is defined, check if it has the required child elements
        exception_type = error_page.find('exception-type')
        if exception_type is None:
            row = ['2.5 Disable client facing Stack Traces', 'exception-type not found', 'No', 'Add exception-type element in web.xml']
            csv_output(row)

        location = error_page.find('location')
        if location is None:
            row = ['2.5 Disable client facing Stack Traces', 'location not found', 'No', 'Add location child element in web.xml']
            csv_output(row)

  # Write the updated web.xml file back to disk
    tree.write(web_xml_path)
  disable_client_facing_stack_traces()
  def turn_off_trace():
    def check_web_xml(app_path):
      web_xml_path = os.path.join(app_path, "WEB-INF", "web.xml")
      if not os.path.isfile(web_xml_path):
        print(f"No web.xml found in {os.path.join(app_path, 'WEB-INF')}")
        return False

      with open(web_xml_path, 'r') as f:
        contents = f.read()
        correct_url_pattern = False
        correct_http_method = False
        correct_web_resource_name = False
        regex = r"<url-pattern>.*\/\*.*<\/url-pattern>"
        if re.search(regex, contents):
          correct_url_pattern = True

        if '<http-method>TRACE</http-method>' in contents:
          correct_http_method = True

        if '<web-resource-name>restricted methods</web-resource-name>' in contents:
          correct_web_resource_name = True

        if correct_url_pattern and correct_http_method and correct_web_resource_name:
          return True
        else:
          if not correct_url_pattern:
            row = [
              '2.6 Turn off TRACE',
              'url-pattern has the wrong value in ' + web_xml_path, 'No',
              'Under security-constraint/web-resource-collection add or modify the value to <url-pattern>/*</url-pattern>'
            ]
            csv_output(row)

          if not correct_http_method:
            row = [
              '2.6 Turn off TRACE',
              'http-method has the wrong value in ' + web_xml_path, 'No',
              'Under security-constraint/web-resource-collection add or modify the value to <http-method>TRACE</http-method>'
            ]
            csv_output(row)

          if not correct_web_resource_name:
            row = [
              '2.6 Turn off TRACE',
              'web-resource-name has the wrong value in ' + web_xml_path, 'No',
              'Under security-constraint/web-resource-collection add or modify the value to <web-resource-name>restricted methods</web-resource-name>'
            ]
            csv_output(row)

          return False

    print("===Section 2.6===")
    for app_name in os.listdir(os.path.join(tomcat_dir, "webapps")):
      app_path = os.path.join(tomcat_dir, "webapps", app_name)
      if os.path.isdir(app_path):
        if not check_web_xml(app_path):
          print()
      else:
        print()
  turn_off_trace()
  def modify_server_header():
      print("===Section 2.7===")

      # Define the server.xml file path
      server_xml_path = os.path.join(tomcat_dir, 'conf', 'server.xml')

      # Parse the server.xml file
      tree = ET.parse(server_xml_path)
      root = tree.getroot()

      # Loop through all Connector elements in the server.xml file
      for connector in root.findall('.//Connector'):

          # Check if the Connector has the xpoweredBy attribute
          if 'xpoweredBy' in connector.attrib:
              apache_regex = re.compile(r'.*apache[-\w]*.*', re.IGNORECASE)
              if re.match(apache_regex, connector.attrib['server']):
                  row = ['2.7 Ensure Server Header is Modified To Prevent Information Disclosure', 'server attribute in the connector element in ' + server_xml_path + ' is revealing on the underlying infrastructure', 'No', 'server=”I am a teapot"']
                  csv_output(row)
              else:
                  print("server attribute is not revealing anything")
          else:
              print("No remedy needed")

      # Write the modified server.xml file
      tree.write(server_xml_path)
      print("Done")
  modify_server_header()