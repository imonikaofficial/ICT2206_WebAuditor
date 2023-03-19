import csv
import os
import xml.etree.ElementTree as ET
from csvoutput import csv_output

def section6():
    print("====Start of Section 6====\n")
    print('Setup Client-cert Authentication\n')
    control_check = '6.1 Setup Client-cert Authentication'
    header_row = [control_check, 'Current Setting', 'Audit Finding', 'Remediation']
    rows = [header_row]
    tomcat_dir = os.getenv('CATALINA_HOME')
    server_xml_path = os.path.join(tomcat_dir, "conf", "server.xml")

    with open(server_xml_path, "r") as f:
        for line in f:
            if "certificateVerification" in line and "required" in line:
                print("certificateVerification is set to required.")
                break
            else:
                current_setting = 'certificateVerification is not set to required.'
                audit_finding = 'Fail'
                remediation = 'In the Connector element, set the clientAuth parameter to true and the certificateVerification to required'
                row = [control_check, current_setting, audit_finding, remediation]
                rows.append(row)
                csv_output(rows)
                print("certificateVerification is not set to required.")

    print('Ensure SSLEnabled is set to True for Sensitive Connectors ')
    server_xml_path = os.path.join(tomcat_dir, "conf", "server.xml")
    tree = ET.parse(server_xml_path)
    root = tree.getroot()

    for connector in root.iter("Connector"):
        if connector.get("SSLEnabled") != "true":
            control_check = '6.2 Ensure SSLEnabled is set to True for Sensitive Connectors'
            current_setting = f"Connector with port {connector.get('port')} does not have SSLEnabled set to true."
            audit_finding = 'Fail'
            remediation = 'In server.xml, set the SSLEnabled attribute to true'
            row = [control_check, current_setting, audit_finding, remediation]
            rows.append(row)
            csv_output(rows)
            print(f"Connector with port {connector.get('port')} does not have SSLEnabled set to true.")

    print('Ensure scheme is set accurately')
    server_xml_path = os.path.join(os.getenv('CATALINA_HOME'), "conf", "server.xml")

    tree = ET.parse(server_xml_path)
    root = tree.getroot()

    for connector in root.iter('Connector'):
        if 'scheme' in connector.attrib and connector.attrib['scheme'] != 'https':
            control_check = '6.3 Ensure scheme is set accurately'
            current_setting = 'The scheme attribute is not set to https in a Connector element.'
            audit_finding = 'Fail'
            remediation = 'In server.xml, set the Connector’s scheme attribute to http for Connectors operating over HTTP'
            row = [control_check, current_setting, audit_finding, remediation]
            rows.append(row)
            csv_output(rows)
            print('The scheme attribute is not set to https in a Connector element.')

    print('Ensure secure is set to true only for SSL-enabled Connectors')
    server_xml_path = os.path.join(os.environ.get("CATALINA_BASE"), "conf", "server.xml")
    with open(os.path.join(tomcat_dir, 'conf', 'server.xml'), 'r') as f:
        lines = f.readlines()
        for i, line in enumerate(lines):
            if '<Connector' in line and 'port="' + connector in line:
                for j in range(i + 1, len(lines)):
                    if '</Connector>' in lines[j]:
                        break
                    if 'SSLEnabled="true"' in lines[j]:
                        if 'secure="true"' not in lines[j]:
                            print('Connector ' + connector + ' should have secure attribute set to true')
                    elif 'SSLEnabled="false"' in lines[j]:
                        if 'secure="false"' not in lines[j]:
                            print('Connector ' + connector + ' should have secure attribute set to false')

    print('Ensure "sslProtocol" is Configured Correctly for Secure Connectors')
    catalina_base = os.getenv('CATALINA_HOME/conf/')
    for dirpath, dirnames, filenames in os.walk(os.path.join(catalina_base, "conf")):
        for filename in filenames:
            if filename == "server.xml":
                server_xml_path = os.path.join(dirpath, filename)

                # Parse server.xml file and loop through all Connector elements
                tree = ET.parse(server_xml_path)
                root = tree.getroot()
                for connector in root.findall("./Service/Connector"):
                    ssl_enabled = connector.get("SSLEnabled")
                    if ssl_enabled == "true":
                        ssl_protocol = connector.get("sslProtocol")
                        if ssl_protocol not in ["TLSv1.2", "TLSv1.3", "TLSv1.2+TLSv1.3"]:
                            control_check = '6.5 Ensure SSLEnabled is set to True for Sensitive Connectors'
                            current_setting = f"WARNING: sslProtocol for {connector.get('port')} is set to {ssl_protocol} instead of TLSv1.2, TLSv1.3, or TLSv1.2+TLSv1.3"
                            audit_finding = 'Fail'
                            remediation = 'In server.xml, set the sslProtocol attribute to TLSv1.2+TLSv1.3 for Connectors having SSLEnabled set to true.'
                            row = [control_check, current_setting, audit_finding, remediation]
                            rows.append(row)
                            csv_output(rows)
                            print(
                                f"WARNING: sslProtocol for {connector.get('port')} is set to {ssl_protocol} instead of TLSv1.2, TLSv1.3, or TLSv1.2+TLSv1.3")
    print("====End of Section 6====")