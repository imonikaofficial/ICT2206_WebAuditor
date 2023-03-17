import csv
import os


def section7(csvFile):
    print('Ensuring application specific logging\n')
    control_check = '7.1  Application specific logging'
    header_row = [control_check, 'Current Setting', 'Audit Finding', 'Remediation']
    rows = [header_row]

    webapps_path = os.path.join(os.environ.get("CATALINA_HOME"), "webapps")
    for dir_name in os.listdir(webapps_path):
        app_path = os.path.join(webapps_path, dir_name)
        if os.path.isdir(app_path):
            logging_props_path = os.path.join(app_path, "WEB-INF", "classes", "logging.properties")
            if os.path.exists(logging_props_path):
                print(f"logging.properties file found in {dir_name}.")
            else:
                current_setting = 'f"logging.properties file not found in {dir_name}."'
                audit_finding = 'Fail'
                remediation = 'Create logging.properites file and place into  WEB-INF/classes directory'
                row = [control_check, current_setting, audit_finding, remediation]
                rows.append(row)
                with open(csvFile, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerows(rows)
                print(f"logging.properties file not found in {dir_name}.")

    print('7.2 Ensure Specification on file handler in logging.properties files')
    app_names = os.listdir(os.path.join(os.environ.get("CATALINA_BASE"), "webapps"))
    for app_name in app_names:
        logging_props_path = os.path.join(os.environ.get("CATALINA_BASE"), "webapps", app_name, "WEB-INF", "classes", "logging.properties")

    if os.path.exists(logging_props_path):
        cmd = f"grep handlers {logging_props_path}"
        result = os.popen(cmd).read()

        if result:
            print(f"Handlers found for {app_name}")
        else:
            print(f"No handlers found for {app_name}")

    print('7.3 Ensuring className is set correctly in context.xml')
    webapps_path = os.path.join(os.environ.get("CATALINA_BASE"), "webapps")

    for app_name in os.listdir(webapps_path):
        context_path = os.path.join(webapps_path, app_name, "META-INF", "context.xml")
        if os.path.exists(context_path):
            cmd = f"grep 'org.apache.catalina.valves.AccessLogValve' {context_path}"
            os.system(cmd)
        else:
            print(f"No context.xml file found for {app_name}.")

    print('Ensure directory in context.xml is a secure location')
    webapps_dir = os.path.join(os.environ.get("CATALINA_BASE"), "webapps")
    tomcat_admin = "tomcat_admin"
    tomcat_group = "tomcat"

    # Loop through each directory in the webapps directory
    for app_name in os.listdir(webapps_dir):
        app_dir = os.path.join(webapps_dir, app_name)
        context_xml_path = os.path.join(app_dir, "META-INF", "context.xml")

        # Check if the context.xml file exists
        if os.path.exists(context_xml_path):
            with open(context_xml_path, "r") as f:
                context_xml = f.read()

                # Extract the directory attribute from the context.xml file
                start_index = context_xml.find("directory=") + len("directory=")
                end_index = context_xml.find('"', start_index)
                directory = context_xml[start_index:end_index]

                # Check the permissions of the directory
                directory_path = os.path.join(app_dir, directory)
                if os.path.exists(directory_path):
                    directory_stat = os.stat(directory_path)
                    owner = pwd.getpwuid(directory_stat.st_uid).pw_name

                    if owner != tomcat_admin:
                        control_check = '7.4 Ensure directory in context.xml is a secure location'
                        current_setting = f"Directory '{directory_path}' is not owned by 'tomcat_admin'"
                        audit_finding = 'Fail'
                        remediation = f"Set the location '{directory_path}' to be owned by tomcat_admin:tomcat"
                        row = [control_check, current_setting, audit_finding, remediation]
                        rows.append(row)
                        with open(csvFile, 'w', newline='') as f:
                            writer = csv.writer(f)
                            writer.writerows(rows)
                        print(f"Directory '{directory_path}' is not owned by 'tomcat_admin'")

                    group = grp.getgrgid(directory_stat.st_gid).gr_name

                    if group != tomcat_group:
                        control_check = '7.4 Ensure directory in context.xml is a secure location'
                        current_setting = f"Directory '{directory_path}' is not owned by group 'tomcat'"
                        audit_finding = 'Fail'
                        remediation = f"Set the location '{directory_path}' to be owned by tomcat_admin:tomcat"
                        row = [control_check, current_setting, audit_finding, remediation]
                        rows.append(row)
                        with open(csvFile, 'w', newline='') as f:
                            writer = csv.writer(f)
                            writer.writerows(rows)
                        print(f"Directory '{directory_path}' is not owned by group 'tomcat'")

                    permissions = oct(directory_stat.st_mode & 0o777)

                    if permissions != "0o700":
                        control_check = '7.4 Ensure directory in context.xml is a secure location'
                        current_setting = f"Directory '{directory_path}' does not have the correct permissions (o-rwx)"
                        audit_finding = 'Fail'
                        remediation = f"Set the location '{directory_path}' to have the correct permissions (o-rwx)"
                        row = [control_check, current_setting, audit_finding, remediation]
                        rows.append(row)
                        with open(csvFile, 'w', newline='') as f:
                            writer = csv.writer(f)
                            writer.writerows(rows)
                        print(f"Directory '{directory_path}' does not have the correct permissions (o-rwx)")
                else:
                    print(f"Directory '{directory_path}' does not exist")
        else:
            print(f"Context.xml file for app '{app_name}' does not exist")

    print('Ensuring pattern in context.xml is correct')
    webapps_path = os.path.join(os.environ.get("CATALINA_BASE"), "webapps")

    for app_name in os.listdir(webapps_path):
        context_xml_path = os.path.join(webapps_path, app_name, "META-INF", "context.xml")

        if os.path.exists(context_xml_path):
            with open(context_xml_path, "r") as f:
                context_xml = f.read()

                if "pattern" in context_xml:
                    print(f"Application {app_name}: pattern setting exists in context.xml")
                else:
                    control_check = '7.5 Ensure directory in context.xml is a secure location'
                    current_setting = f"Application {app_name}: pattern setting does not exist in context.xml"
                    audit_finding = 'Fail'
                    remediation = 'Add the following statement into the location ' + app_name + ' :<Valve className="org.apache.catalina.valves.AccessLogValve" directory="$CATALINA_HOME/logs/" prefix="access_log" fileDateFormat="yyyy-MMdd.HH" suffix=".log" pattern="%h %t %H cookie:%{SESSIONID}c request:%{SESSIONID}r %m %U %s %q %r"/>'
                    row = [control_check, current_setting, audit_finding, remediation]
                    rows.append(row)
                    with open(csvFile, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerows(rows)
                    print(f"Application {app_name}: pattern setting does not exist in context.xml")
        else:
            print(f"Application {app_name}: context.xml does not exist")
