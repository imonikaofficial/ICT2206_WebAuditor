import subprocess
import re
import os
import sys
import csv
import xml.etree.ElementTree as ET
import pwd
import grp

tomcat_dir = os.getenv('CATALINA_HOME')
def section4():
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
  def restrict_access_to_tomcatdir():
      print("===Section 4.1===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      # Expected permissions for group and world
    # Expected file permissions
      EXPECTED_MODE = 0o750  # rwxr-x---
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(tomcat_dir)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.1 Restrict access to $CATALINA_HOME', 'The ownership of $CATALINA_HOME is incorrect', 'No', 'chown tomcat_admin.tomcat $CATALINA_HOME']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {tomcat_dir}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.1 Restrict access to $CATALINA_HOME', 'The permission of $CATALINA_HOME is incorrect', 'No', 'chmod g-w,o-rwx $CATALINA_HOME']
          csv_output(row)
  restrict_access_to_tomcatdir()
  def restrict_access_to_tomcatbase():
      print("===Section 4.2===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      tomcat_base = os.getenv('CATALINA_BASE')

      # Expected permissions for group and world
    # Expected file permissions
      EXPECTED_MODE = 0o750  # rwxr-x---
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(tomcat_base)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.2 Restrict access to $CATALINA_BASE', 'The ownership of $CATALINA_BASE is incorrect', 'No', 'chown tomcat_admin.tomcat $CATALINA_BASE']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {tomcat_base}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.1 Restrict access to $CATALINA_BASE', 'The permission of $CATALINA_BASE is incorrect', 'No', 'chmod g-w,o-rwx $CATALINA_BASE']
          csv_output(row)
  restrict_access_to_tomcatbase()
  def restrict_access_to_tomcatconf():
      print("===Section 4.3===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      conf_path = os.path.join(tomcat_dir, 'conf')
      # Expected permissions for group and world
    # Expected file permissions
      EXPECTED_MODE = 0o750  # rwxr-x---
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(conf_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.3 Restrict access to $CATALINA_HOME/conf', 'The ownership of $CATALINA_HOME/conf is incorrect', 'No', 'chown tomcat_admin.tomcat $CATALINA_HOME/conf']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {conf_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.3 Restrict access to $CATALINA_HOME/conf', 'The permission of $CATALINA_HOME/conf is incorrect', 'No', 'chmod g-w,o-rwx $CATALINA_HOME/conf']
          csv_output(row)
  restrict_access_to_tomcatconf()
  def restrict_access_to_tomcatlogs():
      print("===Section 4.4===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      log_path = os.path.join(tomcat_dir, 'logs')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o770  # rwx-wx---
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(log_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.4 Restrict access to $CATALINA_HOME/logs', 'The ownership of $CATALINA_HOME/logs is incorrect', 'No', 'chown tomcat_admin.tomcat $CATALINA_HOME/logs']
          csv_output(row)
      if actual_mode is None:
        print(f"Could not check file permissions for {log_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.4 Restrict access to $CATALINA_HOME/logs', 'The permission of $CATALINA_HOME/logs is incorrect', 'No', 'chmod o-rwx $CATALINA_HOME/logs']
          csv_output(row)
  restrict_access_to_tomcatlogs()
  def restrict_access_to_tomcattemp():
      print("===Section 4.5===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      temp_path = os.path.join(tomcat_dir, 'temp')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o770  # rwx-wx---
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(temp_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.5 Restrict access to $CATALINA_HOME/temp', 'The ownership of $CATALINA_HOME/temp is incorrect', 'No', 'chown tomcat_admin.tomcat $CATALINA_HOME/temp']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {temp_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.5 Restrict access to $CATALINA_HOME/temp', 'The permission of $CATALINA_HOME/temp is incorrect', 'No', 'chmod o-rwx $CATALINA_HOME/temp']
          csv_output(row)
  restrict_access_to_tomcattemp()
  def restrict_access_to_tomcatbin():
      print("===Section 4.6===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      bin_path = os.path.join(tomcat_dir, 'bin')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o770  # rwx-wx---
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(bin_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.6 Restrict access to $CATALINA_HOME/bin', 'The ownership of $CATALINA_HOME/bin is incorrect', 'No', 'chown tomcat_admin.tomcat $CATALINA_HOME/bin']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {bin_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.6 Restrict access to $CATALINA_HOME/bin', 'The permission of $CATALINA_HOME/bin is incorrect', 'No', 'chmod o-rwx $CATALINA_HOME/bin']
          csv_output(row)
  restrict_access_to_tomcatbin()
  def restrict_access_to_tomcatwebapps():
      print("===Section 4.7===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      webapps_path = os.path.join(tomcat_dir, 'webapps')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o770  # rwx-wx---
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(webapps_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.7 Restrict access to $CATALINA_HOME/webapps', 'The ownership of $CATALINA_HOME/webapps is incorrect', 'No', 'chown tomcat_admin.tomcat $CATALINA_HOME/webapps']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {webapps_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.7 Restrict access to $CATALINA_HOME/webapps', 'The permission of $CATALINA_HOME/webapps is incorrect', 'No', 'chmod o-rwx $CATALINA_HOME/webapps']
          csv_output(row)
  restrict_access_to_tomcatwebapps()
  def restrict_access_to_tomcatcatalina():
      print("===Section 4.8===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      cata_path = os.path.join(tomcat_dir, 'conf', 'catalina.properties')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o600  # rw-------
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(cata_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.8 Restrict access to  $CATALINA_HOME/conf/catalina.properties', 'The ownership of  $CATALINA_HOME/conf/catalina.properties is incorrect', 'No', 'chown tomcat_admin.tomcat  $CATALINA_HOME/conf/catalina.properties']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {cata_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.8 Restrict access to  $CATALINA_HOME/conf/catalina.properties', 'The permission of  $CATALINA_HOME/conf/catalina.properties is incorrect', 'No', 'chmod o-rwx  $CATALINA_HOME/conf/catalina.properties']
          csv_output(row)
  restrict_access_to_tomcatcatalina()
  def restrict_access_to_tomcatcatalinapolicy():
      print("===Section 4.9===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      policy_path = os.path.join(tomcat_dir, 'conf', 'catalina.policy')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o600  # rw-------
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(policy_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.9 Restrict access to  $CATALINA_HOME/conf/catalina.policy', 'The ownership of  $CATALINA_HOME/conf/catalina.policy is incorrect', 'No', 'chown tomcat_admin.tomcat  $CATALINA_HOME/conf/catalina.policy']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {policy_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.9 Restrict access to  $CATALINA_HOME/conf/catalina.policy', 'The permission of  $CATALINA_HOME/conf/catalina.policy is incorrect', 'No', ' chmod 600 $CATALINA_HOME/conf/catalina.policy']
          csv_output(row)
  restrict_access_to_tomcatcatalinapolicy()
  def restrict_access_to_tomcatcontext():
      print("===Section 4.10===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      context_path = os.path.join(tomcat_dir, 'conf', 'context.xml')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o600  # rw-------
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(context_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.10 Restrict access to  $CATALINA_HOME/conf/context.xml', 'The ownership of  $CATALINA_HOME/conf/context.xml is incorrect', 'No', 'chown tomcat_admin.tomcat  $CATALINA_HOME/conf/context.xml']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {context_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.10 Restrict access to  $CATALINA_HOME/conf/context.xml', 'The permission of  $CATALINA_HOME/conf/context.xml is incorrect', 'No', ' chmod 600 $CATALINA_HOME/conf/context.xml']
          csv_output(row)
  restrict_access_to_tomcatcontext()
  def restrict_access_to_tomcatloggingproperties():
      print("===Section 4.11===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      loggingproperties_path = os.path.join(tomcat_dir, 'conf', 'logging.properties')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o600  # rw-------
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(loggingproperties_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.11 Restrict access to  $CATALINA_HOME/conf/ logging.properties', 'The ownership of  $CATALINA_HOME/conf/ logging.properties is incorrect', 'No', 'chown tomcat_admin.tomcat  $CATALINA_HOME/conf/ logging.properties']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {loggingproperties_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.11 Restrict access to  $CATALINA_HOME/conf/logging.properties', 'The permission of  $CATALINA_HOME/conf/logging.properties is incorrect', 'No', ' chmod 600 $CATALINA_HOME/conf/logging.properties']
          csv_output(row)
  restrict_access_to_tomcatloggingproperties()
      def restrict_access_to_tomcatserver():
      print("===Section 4.12===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      server_path = os.path.join(tomcat_dir, 'conf', 'server.xml')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o600  # rw-------
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(server_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.12 Restrict access to  $CATALINA_HOME/conf/ server.xml', 'The ownership of  $CATALINA_HOME/conf/ server.xml is incorrect', 'No', 'chown tomcat_admin.tomcat  $CATALINA_HOME/conf/ server.xml']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {server_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.12 Restrict access to  $CATALINA_HOME/conf/server.xml', 'The permission of  $CATALINA_HOME/conf/server.xml is incorrect', 'No', ' chmod 600 $CATALINA_HOME/conf/server.xml']
          csv_output(row)
  restrict_access_to_tomcatserver()
  def restrict_access_to_tomcatusers():
      print("===Section 4.13===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      users_path = os.path.join(tomcat_dir, 'conf', 'tomcat-users.xml')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o600  # rw-------
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(users_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.13 Restrict access to  $CATALINA_HOME/conf/ tomcat-users.xml', 'The ownership of  $CATALINA_HOME/conf/tomcat-users.xml is incorrect', 'No', 'chown tomcat_admin.tomcat  $CATALINA_HOME/conf/tomcat-users.xml']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {users_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.13 Restrict access to  $CATALINA_HOME/conf/tomcat-users.xml', 'The permission of  $CATALINA_HOME/conf/tomcat-users.xml is incorrect', 'No', ' chmod 600 $CATALINA_HOME/conf/tomcat-users.xml']
          csv_output(row)
  restrict_access_to_tomcatusers()
  def restrict_access_to_tomcatwebxml():
      print("===Section 4.14===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      webxml_path = os.path.join(tomcat_dir, 'conf', 'web.xml')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o400  # rw-------
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(webxml_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.14 Restrict access to  $CATALINA_HOME/conf/ web.xml', 'The ownership of  $CATALINA_HOME/conf/web.xml is incorrect', 'No', 'chown tomcat_admin.tomcat  $CATALINA_HOME/conf/web.xml']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {webxml_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.14 Restrict access to  $CATALINA_HOME/conf/web.xml', 'The permission of  $CATALINA_HOME/conf/web.xml is incorrect', 'No', ' chmod 400 $CATALINA_HOME/conf/web.xml']
          csv_output(row)
  restrict_access_to_tomcatwebxml()
  def restrict_access_to_tomcatjaspic():
      print("===Section 4.15===")
      EXPECTED_USER = "tomcat_admin"
      EXPECTED_GROUP = "tomcat"

      jaspic_path = os.path.join(tomcat_dir, 'conf', 'jaspic-providers.xml')
      # Expected permissions for group and world
      EXPECTED_MODE = 0o600  # rw-------
      # Get the actual user and group of the directory
      try:
          stat_info = os.stat(jaspic_path)
          actual_user = pwd.getpwuid(stat_info.st_uid).pw_name
          actual_group = grp.getgrgid(stat_info.st_gid).gr_name
          actual_mode = stat_info.st_mode
      except OSError:
          actual_user = None
          actual_group = None
          actual_mode = None
      
      # Check if the actual user and group match the expected ones
      if actual_user != EXPECTED_USER and actual_group != EXPECTED_GROUP:
          row = ['4.15 Restrict access to  $CATALINA_HOME/conf/jaspic-providers.xml', 'The ownership of  $CATALINA_HOME/conf/jaspic-providers.xml is incorrect', 'No', 'chown tomcat_admin.tomcat  $CATALINA_HOME/conf/jaspic-providers.xml']
          csv_output(row)

      if actual_mode is None:
        print(f"Could not check file permissions for {jaspic_path}.")
      else:
        if actual_mode != EXPECTED_MODE:
          row = ['4.15 Restrict access to  $CATALINA_HOME/conf/jaspic-providers.xml', 'The permission of  $CATALINA_HOME/conf/jaspic-providers.xml is incorrect', 'No', ' chmod 600 $CATALINA_HOME/conf/jaspic-providers.xml']
          csv_output(row)
  restrict_access_to_tomcatjaspic()
