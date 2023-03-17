import csv
import os
import xml.etree.ElementTree as ET

def section9(csvFile):
    print('Ensuring Tomcat starts with Security Manager\n')
    control_check = '9.1 Starting Tomcat with Security Manager'
    header_row = [control_check, 'Current Setting', 'Audit Finding', 'Remediation']
    rows = [header_row]
    catalina_home = os.getenv('CATALINA_HOME')




    print('Ensuring auto deployment of applications is disabled')
    server_xml_path = os.getenv('CATALINA_HOME/conf/server.xml')
    tree = ET.parse(server_xml_path)
    root = tree.getroot()
    for connector in root.findall("./Service/Connector"):
        if connector.get("port") == "8080":
            if connector.get("autoDeploy") != "false":
                control_check = '9.2 Disabling auto deployment of applications'
                current_setting = 'autoDeploy is not set to false in server.xml'
                audit_finding = 'Fail'
                remediation = 'In the $CATALINA_HOME/conf/server.xml file, change autoDeploy to false'
                row = [control_check, current_setting, audit_finding, remediation]
                rows.append(row)
                with open(csvFile, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerows(rows)
                print("autoDeploy is not set to false in server.xml")

    print('Ensuring deploy on startup of applications is disabled')
    server_xml_file = os.getenv('CATALINA_HOME/conf/server.xml')
    tree = ET.parse(server_xml_file)
    root = tree.getroot()
    for service in root.findall("Service"):
        for engine in service.findall("Engine"):
            deployer = engine.find("Host/Context")
            if deployer is not None:
                if deployer.get("deployOnStartup") != "false":
                    control_check = '9.3  Disable deploy on startup of applications'
                    current_setting = 'deployOnStartup is not set to false in server.xml'
                    audit_finding = 'Fail'
                    remediation = 'In the $CATALINA_HOME/conf/server.xml file, change deployOnStartup to false'
                    row = [control_check, current_setting, audit_finding, remediation]
                    rows.append(row)
                    with open(csvFile, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerows(rows)
                    print("deployOnStartup is not set to false in server.xml")

