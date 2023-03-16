import subprocess
import re
import xlsxwriter
import argparse
import subprocess
import json
import urllib.request
import pandas as pd
import requests
import os
import sys
from bs4 import BeautifulSoup
from colorama import Fore


def check_nginx_installed():
    # run the nginx -v command and use grep to extract the version number
    grep_command = "nginx -v 2>&1 | grep -Po '(?<=nginx/)[0-9]+.[0-9]+.[0-9]+'"
    nginx_version = subprocess.check_output(grep_command, shell=True).decode().strip()
    # Create a new Excel file
    workbook = xlsxwriter.Workbook('nginx_output.xlsx')
    worksheet = workbook.add_worksheet()
    # Write headers for the columns
    headers = ['Control Check', 'Current Setting', 'Audit Finding', 'Remediation']
    worksheet.write_row('A1', headers)
    # Write data to the worksheet
    data = ['Ensure NGINX is installed and check the version', str(nginx_version), '', '']
    worksheet.write_row('A2', data)
    if nginx_version:
        print(f"Running nginx version {nginx_version}")
        url = "https://packages.ubuntu.com/focal-updates/nginx"
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        version_tag = soup.find('h1', text=re.compile(r'nginx \(\d+\.\d+\.\d+-\dubuntu\d+(\.\d+)?\)'))
        version_string = version_tag.text.strip()
        latest_version = re.search(r'\d+\.\d+(\.\d+)?', version_string).group()
        if latest_version > nginx_version:
            print(f"[-] NGINX web server is out of date,The current version is: {nginx_version} and latest version is: {latest_version}")
            audit_finding = 'Yes'
            remediate = input("Do you want to update NGINX to the latest version? (y/n) ")
            if remediate.lower() == "y":
                # install_nginx = "git clone https://github.com/nginx/nginx.git"
                # subprocess.run(install_nginx, shell=True)
                subprocess.run(['sudo', 'apt-get', 'update'])
                subprocess.run(['sudo', 'apt-get', 'install', 'nginx'])
                print("[+] NGINX has been updated to the latest version")
                remediation = 'NGINX updated to latest version'
            
            elif remediate.lower() == "n":
                print("[+] NGINX has not been updated to the latest version")
                audit_finding = 'Yes'
                remediation = 'NGINX not updated'
            
            else:
                print("[+] NGINX has not been updated")
                audit_finding = 'Yes'
                remediation = 'N/A'
        else:
            print(f"[+] NGINX version is up to date")
            audit_finding = 'Yes'
    else:
        print("Unable to determine nginx version")
        audit_finding = 'Unable to determine nginx version'
        remediation = 'N/A'
      # Write data to the worksheet
    data = ['Ensure NGINX is installed and check the version', str(nginx_version), audit_finding, remediation]
    worksheet.write_row('A2', data)
    workbook.close()

    # Read the Excel file into a pandas DataFrame
    df = pd.read_excel('nginx_output.xlsx')

    # Convert the DataFrame to a CSV file
    df.to_csv('nginx_output.csv', index=False)
def installed_from_source():
    # Check if nginx is installed from source
    grep_command = "nginx -v 2>&1 | grep -Po '(?<=nginx/)[0-9]+.[0-9]+.[0-9]+'"
    installed_from_source = int(subprocess.check_output(grep_command, shell=True).decode().strip())
    
    if installed_from_source:
        print("NGINX is installed from source.")
        # Get the current version number from nginx -v
        grep_command = "nginx -v 2>&1 | grep -Po '(?<=nginx/)[0-9]+.[0-9]+.[0-9]+'"
        nginx_version = subprocess.check_output(grep_command, shell=True).decode().strip()
        print(f"Current NGINX version is {nginx_version}")
        
        # Get the latest version number from GitHub
        url = "https://github.com/nginx/nginx/tags"
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        release_url = soup.find('a', attrs={'href': re.compile("^/nginx/nginx/releases/tag")}).get('href')
        latest_version = release_url.split("-")[1]
        print(f"Latest NGINX version is {latest_version}")
        
        if latest_version > nginx_version:
            print(f"[-] NGINX web server is out of date,The current version is: {nginx_version} and latest version is: {latest_version}")
            remediate = input("Do you want to update NGINX to the latest version? (y/n) ")
            if remediate.lower() == "y":
                # Download and install the latest version
                wget_command = f"wget https://nginx.org/download/nginx-{latest_version}.tar.gz"
                os.system(wget_command)
                tar_command = f"tar zxf nginx-{latest_version}.tar.gz"
                os.system(tar_command)
                cd_command = f"cd nginx-{latest_version}"
                os.system(cd_command)
                configure_command = "./configure --with-http_stub_status_module"
                os.system(configure_command)
                make_command = "make"
                os.system(make_command)
                make_install_command = "make install"
                os.system(make_install_command)
                print("[+] NGINX has been updated to the latest version")
            elif remediate.lower() == "n":
                print("[-] NGINX has not been updated to the latest version")
            else:
                print("[-] NGINX has not been updated")
        else:
            print(f"[-] NGINX version is up to date")
    else:
        print("NGINX is not installed from source.")
    
    # Get the current version number from nginx -v
    grep_command = "nginx -v 2>&1 | grep -Po '(?<=nginx/)[0-9]+.[0-9]+.[0-9]+'"
    nginx_version = subprocess.check_output(grep_command, shell=True).decode().strip()
    
    # Create a new Excel file
    workbook = xlsxwriter.Workbook('nginx_output.xlsx')
    worksheet = workbook.add_worksheet()

def account_security():

    nginxfolderDir = r'/etc/nginx/'
    if not os.path.isdir(nginxfolderDir):
        nginxfolderDir = input('Enter the location of the config folder: ')
    nginx_configfile = '{}/nginx.conf'.format(nginxfolderDir)
    if not os.path.isfile(nginx_configfile):
        nginx_configfile = input('Enter the location of the main config file: ')

    # Use subprocess to execute the command
    grep_command = "grep -i ^user {} ".format(nginx_configfile)
    get_acc = subprocess.check_output(grep_command, shell=True).decode().strip()
    users =['nginx','www-data']
    if get_acc :
       user = get_acc.split('user ')[1].replace('\n', '').rstrip(';')
       users =['nginx','www-data']
       www = users[1]
       nginx = users[0]
       if user == www:
          print(f"A dedicated nginx user called {user} exists")
          priv_command = "sudo -l -U {} |  grep -io 'not allowed to run sudo'".format(user)
          get_priv = subprocess.check_output(priv_command, shell=True).decode().strip()
          if get_priv:
             print(f"[+] A dedicated nginx user called {user} is not privileged")
             grp_command = f"groups {user}  | grep -io '{user} : {user}' "
             get_grp = subprocess.check_output(grp_command, shell=True).decode().strip()
             if get_grp:
                print(f"[+] The nginx dedicated user {user} is not part of any unexpected groups")
             elif not get_grp:
                print(f"[-] The nginx dedicated user {user} is part of anunexpected groups")
             else:
                print('[-] No nginx group found')
                print('[-] Make sure that a dedicated group directive present in the {} file\n'.format(nginx_configfile))
          else:
            print(f"[-] A dedicated nginx user called {user} is privileged")        
       elif user == nginx :
          print(f"[+] A dedicated nginx user called {user} exists")
          priv_command = "sudo -l -U {} |  grep -io 'not allowed to run sudo'".format(user)
          get_priv = subprocess.check_output(priv_command, shell=True).decode().strip()
          if get_priv:
             print(f"[-] A dedicated nginx user called {user} is not privileged")
             grp_command = f"groups {user}  | grep -io '{user} : {user}' "
             get_grp = subprocess.check_output(grp_command, shell=True).decode().strip()
             if get_grp:
                print(f"[+] The nginx dedicated user {user} is not part of any unexpected groups")
             elif not get_grp:
                print(f"[-] The nginx dedicated user {user} is part of an unexpected groups")
             else:
                print('[-] No nginx group found')
                print('[-] Make sure that a dedicated group directive present in the {} file\n'.format(nginx_configfile))
          else:
            print(f"[-] A dedicated nginx user called {user} is  privileged")                   
       else:
          print(f"[-] {user} is not a dedicated user")      
    elif not get_acc:
       print('[-] A dedicated nginx user does not exist')
       print('[-] Make sure that a dedicated user directive exist in the {} file\n'.format(nginx_configfile))
       remediate = input("Do you want to fix this issue? (y/n) ")
       
       if remediate.lower() == "y":
          nginxDir = r'/var/cache/nginx '
          if not os.path.isdir(nginxDir):
             nginxDir = input('Enter the location of the config folder: ')
          useradd = input("Input the user name ")
          grep_command = f"useradd {useradd} -r -g nginx -d {nginxDir} -s /sbin/nologin"
          os.system(grep_command)
          add_command = f"user {useradd} "
          os.system(add_command)
          reload_command = "systemctl restart nginx"
          os.system(reload_command)    
          print("[+] A system account is added for the nginx user")
       elif remediate.lower() == "n":
           print("[-] A system account is not added for the nginx user")
       else:
           print("[-] Something wrong has occured")
    else:
      print('[-] A dedicated nginx user does not exist')   

# Ensure Nginx User is Locked
    if os.popen('passwd -S {}'.format(user)).read().split()[1] != 'L':
       print('[-] The nginx user should be locked') 
       remediate = input("Do you want to fix this issue? (y/n) ")
       
       if remediate.lower() == "y":   
          grep_command = f"passwd -l {user}"
          os.system(grep_command)
       elif remediate.lower() == "n":
          print('[-] The nginx user is not locked')          
    else:
       print('[+] The nginx user is not locked') 
# Ensure Nginx User Account has Invalid Shell
    if not os.popen("grep {} /etc/passwd | grep -io '/sbin/nologin'".format(user)).read():
       print('[-] Nginx user should not have an invalid login shell')
       remediate = input("Do you want to fix this issue? (y/n) ")
       if remediate.lower() == "y":   
          grep_command = f"usermod -s /sbin/nologin {user}"
          os.system(grep_command)
       elif remediate.lower() == "n":
          print('[-] The nginx user still has an invalid login shell')            
    else:
       print('[+] The nginx user does not have an invalid login shell')         
       grep_command = f"usermod -s /sbin/nologin {user}"
       os.system(grep_command)
       
def directories_perms():
    configDir = r'/etc/nginx'
    if not os.path.isdir(configDir):
        configDir = input('Enter the location of the config folder:')
    # Use subprocess to execute the command
    grep_command = f" stat {configDir}  | grep -io ' Uid: (    0/' "
    uid_root= subprocess.check_output(grep_command, shell=True).decode().strip()
        # Use subprocess to execute the command
    grep_command1 = f" stat {configDir}  | grep -io ' Gid: (    0/' "
    gid_root= subprocess.check_output(grep_command1, shell=True).decode().strip()
    if not uid_root :
        remediate = input("Do you want to fix this issue? (y/n) ")
        if remediate.lower() == "y":   
          grep_command = f"chown -R root:root {configDir}"
          os.system(grep_command)
          print(f"[+] The {configDir} directory's uid is changed to root ")     
        elif remediate.lower() == "n":
          print(f"[-] The {configDir} directory's uid is still not root ")          
    elif not gid_root:
        remediate = input("Do you want to fix this issue? (y/n) ")
        if remediate.lower() == "y":   
          grep_command = f"chown -R root:root {configDir}"
          os.system(grep_command)
          print(f"[+] The {configDir} directory's gid is changed to root ")            
        elif remediate.lower() == "n":
          print(f"[-] The {configDir} directory's gid is still not root ")   
    else:
        print(f"[+] The {configDir} directory's gid and uid is set to root ")   
        grep_command = f" stat {configDir} "
        os.system(grep_command)       
#check agn       
def restricted_perms():
    configDir = r'/etc/nginx'
    if not os.path.isdir(configDir):
        configDir = input('Enter the location of the config folder:')
    for root, dirs,files  in os.walk(configDir):
        for name in dirs:
            path= os.path.join(root, name)
    
    # Use subprocess to execute the command
    grep_command = f" stat {configDir} | grep -io 755 "
    grep_command1 = f" stat {path} | grep -io 755 "
    
    try:
      nginx_perm= subprocess.check_output(grep_command, shell=True).decode().strip()
      nginx_perm_int = int(nginx_perm)
      dir_perm= subprocess.check_output(grep_command1, shell=True).decode().strip()
      dir_perm_int = int(dir_perm)  
      if not nginx_perm_int <= 755:
        remediate = input("Do you want to fix this issue? (y/n) ")
        if remediate.lower() == "y":   
          grep_command = f" sudo chmod go-w {configDir}  "
          os.system(grep_command)
          print(f"[+] Permissions are set with the ability to read as other by default on the configuration directory {configDir}: -rw-r--r-- ")     
        elif remediate.lower() == "n":
          print(f"[-] Permissions are not set with the ability to read as other by default on the configuration directory {configDir}: -rw-r--r-- ")     
      elif not dir_perm_int <= 755:
        for root, dirs,files  in os.walk(configDir):
          for name in dirs:
            path1= os.path.join(root, name)
            remediate = input("Do you want to fix this issue? (y/n) ")
            if remediate.lower() == "y":   
               grep_command = f"sudo chmod go-w {path1}  "
               os.system(grep_command)
               print(f"[+] Permissions are set with the ability to read as other by default on the configuration directory {path1}: -rw-r--r-- ")     
            elif remediate.lower() == "n":
               print(f"[-] Permissions are not set with the ability to read as other by default on the configuration directory {path1}: -rw-r--r-- ")
                 
      else:
           print(f"[+] Access to NGINX directories are restricted ")   
           grep_command = f" stat {configDir} | grep -io 755 "
           print(f"[+] Access to /etc/nginx directory is restricted: ")   
           os.system(grep_command)  
           for root, dirs,files  in os.walk(configDir):
            for name in dirs:
                path= os.path.join(root, name)
                print(f"[+] Access to NGINX directory {path}  is restricted ") 
                grep_command1 = f" stat {path} | grep -io 755 "
                os.system(grep_command1)            
    except subprocess.CalledProcessError as e:
                print(f"[-] Error checking permissions for the files : {e}")
                grep_command = "sudo find /etc/nginx -type d -exec stat -Lc '%n %a'{} + "
                os.system(grep_command)
    grep_command3 = "sudo find /etc/nginx -type f -exec stat -Lc '%a' {} + "
    try:
        file_perm = subprocess.check_output(grep_command3, shell=True).decode().strip()
        file_perm_int = int(file_perm)  
        if not file_perm_int <= 660:
           remediate = input("Do you want to fix this issue? (y/n) ")
           if remediate.lower() == "y":
                grep_command = "sudo find /etc/nginx -type f -exec chmod ug-x,o-rwx {} + "
                os.system(grep_command)
                print(f"[+] Permissions are set with the ability to read and execute as other by default on directory file : drwxr-xr-x ")
           elif remediate.lower() == "n":
                print(f"[-] Permissions are not set with the ability to read and execute as other by default on directory file : drwxr-xr-x ")
        elif  file_perm_int <= 660:
            remediate = input("Do you want to fix this issue? (y/n) ")
            if remediate.lower() == "y":
               grep_command = "sudo find /etc/nginx -type f -exec chmod ug-x,o-rwx {} +"
               os.system(grep_command)
               print(f"[+] Permissions are set with the ability to read and execute as other by default on directory file : drwxr-xr-x ")
            elif remediate.lower() == "n":
               print(f"[-] Permissions are set with the ability to read and execute as other by default on directory file : drwxr-xr-x ")
        else:
               print(f"[+] Access to NGINX directory  is restricted: drwxr-xr-x")
               grep_command3 = "sudo find /etc/nginx -type f -exec stat -Lc '%n %a' {} +"
               os.system(grep_command3) 
                                            
    except subprocess.CalledProcessError as e:
               print(f"[-] Error checking permissions for the files : {e}")
               grep_command3 = "sudo find /etc/nginx -type f -exec stat -Lc '%n %a' {} +"
               os.system(grep_command3)
                 

def secure_pid():

    nginxfolderDir = r'/var/run/'
    if not os.path.isdir(nginxfolderDir):
        nginxfolderDir = input('Enter the location of the config folder: ')
    nginx_configfile = '{}nginx.pid'.format(nginxfolderDir)
    if not os.path.isfile(nginx_configfile):
        nginx_configfile = input('Enter the location of the main config file: ')
    # Use subprocess to execute the command
    grep_command = f" stat -L -c '%U:%G' {nginx_configfile} "
    own = subprocess.check_output(grep_command, shell=True).decode().strip()
    grep_command1 = f"  stat -L -c '%a' {nginx_configfile} "
    perm = subprocess.check_output(grep_command1, shell=True).decode().strip()
    perm_int = int(perm)  
    if not own == "root:root" :
        print(f"[-] The PID file is not owned by root, it is owned by {own}")
        remediate = input("Do you want to fix this issue? (y/n) ")
        if remediate.lower() == "y":   
          grep_command = f" chown root:root {nginx_configfile}  "
          os.system(grep_command)
          print(f"[+] The PID file {nginx_configfile} is now owned by root ")     
        elif remediate.lower() == "n":
          print(f"[-] The PID file {nginx_configfile} is still not owned by root ")           

    elif not perm_int >= 644 :
          print(f"[-] The PID file {nginx_configfile}'s permissions is not set to 644 ")    
          remediate = input("Do you want to fix this issue? (y/n) ")
          if remediate.lower() == "y":   
           grep_command = f" chmod u-x,go-wx  {nginx_configfile}  "
           os.system(grep_command)
           print(f"[+] The PID file {nginx_configfile}'s permissions is now set correctly ")     
          elif remediate.lower() == "n":
           print(f"[-] The PID file {nginx_configfile}'s permissions is still not set correctly   ")              
               
    else:
           print("The PID file's ownership and permissions are set correctly")
           grep_command3 = f"stat -L -c '%U:%G' {nginx_configfile} && stat -L -c '%a' {nginx_configfile}"
           os.system(grep_command3)



def  coredir_secure():
    
    configDir = r'/etc/nginx'
    if not os.path.isdir(configDir):
        configDir = input('Enter the location of the config folder:')
    # Use subprocess to execute the command
    grep_command = f" stat {configDir}  | grep -io ' Uid: (    0/' "
    uid_root= subprocess.check_output(grep_command, shell=True).decode().strip()
        # Use subprocess to execute the command
    grep_command1 = f" stat {configDir}  | grep -io ' Gid: (    0/' "
    gid_root= subprocess.check_output(grep_command1, shell=True).decode().strip()
    if not uid_root :
        remediate = input("Do you want to fix this issue? (y/n) ")
        if remediate.lower() == "y":   
          grep_command = f"chown -R root:root {configDir}"
          os.system(grep_command)
          print(f"[+] The {configDir} directory's uid is changed to root ")     
        elif remediate.lower() == "n":
          print(f"[-] The {configDir} directory's uid is still not root ")          
    elif not gid_root:
        remediate = input("Do you want to fix this issue? (y/n) ")
        if remediate.lower() == "y":   
          grep_command = f"chown -R root:root {configDir}"
          os.system(grep_command)
          print(f"[+] The {configDir} directory's gid is changed to root ")            
        elif remediate.lower() == "n":
          print(f"[-] The {configDir} directory's gid is still not root ")   
    else:
        print(f"[-] The {configDir} directory's gid and uid is set to root ")   
        grep_command = f" stat {configDir} "
        os.system(grep_command)       
                                                              
def block_ips():
  print("[+] Block IP addresses that have tried to conduct malicious injections of the web server's URL ")
  access_log_path = r'/var/log/nginx/access.log'
  payload = r'payloads.txt'
  nginxfolderDir = r'/etc/nginx/conf.d/'
  blockips_conf_path = r'{}blockips.conf'.format(nginxfolderDir)
  if not os.path.isdir(nginxfolderDir):
        nginxfolderDir = input('Enter the location of the config folder for nginx: ')
  if not os.path.isfile(blockips_conf_path):
        blockips_conf_path = input('Enter the location of the ip blacklist file : ')              

  if not os.path.isdir(access_log_path):
        access_log_path = input('Enter the location of the access-log file: ')
  
  if not os.path.isdir(payload):
        payload = input('Enter the location of the payload text file: ')
  nginxfolder = r'/etc/nginx/'
  if not os.path.isdir(nginxfolder):
        nginxfolder = input('Enter the location of the config folder (/etc/nginx): ')
  nginx_configfile = '{}/nginx.conf'.format(nginxfolder)
  if not os.path.isfile(nginx_configfile):
        nginx_configfile = input('Enter the location of the main nginx config file: ')
  payloads = []    
  with open(payload,'r')  as file:
    for line in file:
      payloads.append(line.strip())
  # Read access log file and extract IP addresses
  def read_access_log():
        ip_set = set()
        with open(access_log_path) as f:
            for line in f:
                for payload in payloads:
                    if payload in line.lower():
                        ip = line.split()[0]
                        ip_set.add(ip)
        return ip_set
  # Block IP addresses
  def block_ips(ip_set):
        if not ip_set:
           print("[+] No IP addresses connected to the web server has performed malicious injections ")
        with open(blockips_conf_path, 'w') as f:
            f.write('geo $blocked_ips {\n')
            f.write('    default 0;\n')
            for ip in ip_set:
                f.write('    {0} 1;\n'.format(ip))
            f.write('}\n')
            print("[+] Blacklisted the IP addresses successfully at blockips.conf file and add the file name on the nginx.conf as 'include {your_blockips.conf_path}' under http and add the following in /etc/nginx/sites-enabled/* if you have enabled vhosts the following: \n if ($blocked_ips) \n{\nreturn 403;\n}  under location /")
        grep_command = "sudo systemctl restart nginx"
        os.system(grep_command)
  ip_set = read_access_log()
  block_ips(ip_set)        
  
def crlf_injections():
 crlf_payloads = ["%0d%0a", "%0d%0aSet-Cookie: testcookie=test", "%0d%0aLocation: http://evil.com"]

 for payload in crlf_payloads:
    crlf_req = requests.get(url  + payload, verify=False)

    if "testcookie=test" in crlf_req.text or "Location: http://evil.com" in crlf_req.text:
        print("CRLF injection vulnerability found with payload:", payload)
    else:
        print("No CRLF injection vulnerability with payload:", payload) 
        
def network_conn():
    print("[+] Check whether NGINX only listens for network connections on authorized ports  ")
    # Use subprocess to execute the command
    grep_command = "find /etc/nginx -type f,d -not -path '/etc/nginx/*' -exec grep -rE 'listen[^;]*;' {} + | grep -E '80' "
    grep_command1 = "find /etc/nginx -type f,d -not -path '/etc/nginx/*' -exec grep -rE 'listen[^;]*;' {} + | grep -E '443' "
    try:
      listen_net= subprocess.check_output(grep_command, shell=True).decode().strip()
      if not (listen_net):
           print("[-]  NGINX does not listen to authorized ports like 80")
           os.system(grep_command)
      elif (listen_net  )  is None :
           print("[-] NGINX does not listen to any ports   ")
           os.system(grep_command)
      else:
           print("[+] NGINX only listens for network connections on authorized ports like 80  ")   
           os.system(grep_command)         
    except subprocess.CalledProcessError as e:
                print(f"[-] Error checking for connections : {e}")
                os.system(grep_command)
    try:
      listen_net1= subprocess.check_output(grep_command1, shell=True).decode().strip()
      if not (listen_net1):
           print("[-]  NGINX does not listen to authorized ports like 443")
           print("Remediation : Comment out or delete the associated configuration for that listener")
           os.system(grep_command1)
      elif (listen_net  )  is None :
           print("[-] NGINX does not listen to any ports  ")
           os.system(grep_command1)
      else:
           print("[+] NGINX only listens for network connections on authorized ports like 443  ")   
           os.system(grep_command1)         
    except subprocess.CalledProcessError as e:
                print(f"[-] Unable to check for connections as the some files in the /etc/nginx  directory don't have listners,thus check manually for those files ")
                os.system(grep_command1)
    print("[+] Check for files under the conf.d directory and check whether they listen for connections and add the output.txt generated with the filenames to continue")
    grep_conf = "grep -E 'include\s+/etc/nginx/conf\.d/[^;]+\.conf;' /etc/nginx/nginx.conf | grep -o '/etc/nginx/conf\.d/[^;]\+\.conf' > output.txt"    
    os.system(grep_conf)
    output_file = r'output.txt'
    if not os.path.isdir(output_file):
        output_file = input('Enter the name of the output file: ')    
    outputs = []    
    with open(output_file,'r')  as file:
     for line in file:
      outputs.append(line.strip()) 
     
    try:
      for output in outputs:
          if output in line.lower():
             grep_command1 = f"grep -ir 'listen[^;]*;' {output} | grep -E '80' "
      listen_net= subprocess.check_output(grep_command1, shell=True).decode().strip()
      if not (listen_net ):
           print("[-]  NGINX does not listen to authorized ports like 80")
           os.system(grep_command1)
      elif (listen_net  )  is None :
           print("[-] NGINX does not listen to any ports   ")
           os.system(grep_command1)
      else:
           print("[+] NGINX only listens for network connections on authorized ports like 80  ")   
           os.system(grep_command1)         
    except subprocess.CalledProcessError as e:
                print(f"[-] Unable to check for connections as the some files in the conf.d directory don't have listners, thus check manually for those files ")
                cat_output ="cat output.txt"
                os.system(cat_output)      
    try:
      for output in outputs:
          if output in line.lower():
             grep_command2 = f"grep -ir 'listen[^;]*;' {output}| grep -E '443' "
      listen_net1= subprocess.check_output(grep_command2, shell=True).decode().strip()
      if not (listen_net1 ):
           print("[-]  NGINX does not listen to authorized ports like 443")
           os.system(grep_command1)
      elif (listen_net1  )  is None :
           print("[-] NGINX does not listen to any ports ")
           os.system(grep_command1)
      else:
           print("[+] NGINX only listens for network connections on authorized ports like 443  ")   
           os.system(grep_command1)         
    except subprocess.CalledProcessError as e:
                print(f"[-] Unable to check for connections as the some files in the conf.d directory don't have listners, thus check manually for those files ")
                cat_output ="cat output.txt"
                os.system(cat_output)             
def curl_host(url):
  print("[+] Check whether NGINX only listens for network connections on authorized ports  ")
  try:
    curl_cmd = f"curl -k -v --silent {url} -H 'Host: invalid.host.com' --stderr - "
    response = subprocess.check_output(curl_cmd, shell=True).decode().strip()
    # extract HTTP response codes using regex
    codes = re.findall(r"HTTP/\d\.\d (\d+)|HTTP/\d\.\d 4\d{2}", response)
    # convert list to string
    codes_str = " ".join(codes)
    response_int = int(codes_str)
    if response_int >= 400:
        print("[+] Requests for unknown host names are being rejected")
        print(f"HTTP response code: {response_int}")
    else:
        print("[-] Requests for unknown host names are not being rejected")
        print(f"HTTP response code: {response_int}")
        example = '''
        server {
          return 404;
            }
        '''
        print("Remediation : \nEnsure your first server block mirrors the below in your nginx configuration, either at /etc/nginx/nginx.conf or any included file within your nginx config:\n" + example )    
  except subprocess.CalledProcessError :
    print("[+] Requests for unknown host names are not being rejected")
    bad_curl_cmd = f"  curl -k -v --silent {url} -H 'Host: invalid.host.com' 2>&1 | head -n 10 "
    os.system(bad_curl_cmd)
    example = '''
        server {
          return 404;
            }
        '''
    print("Remediation : \nEnsure your first server block mirrors the below in your nginx configuration, either at /etc/nginx/nginx.conf or any included file within your nginx config:\n" + example )    
def keepalive_timeout():
  print("[+] Ensure keepalive_timeout is 10 seconds or less, but not 0 ")
  try:
    grep_command = "grep -ir keepalive_timeout /etc/nginx"
    output = subprocess.check_output(grep_command, shell=True, text=True)
# extract the number between 1-10 using regex
    number = re.findall(r"([1-9]|10)", output)[0]
    response_int = int(number)  
    if response_int <= 10:
        print("[+] Timeout is set to 10 seconds or less")
        os.system(grep_command)         
    elif response_int == 0:
        print("[-] Timeout is set to 0")
        os.system(grep_command)   
        example = '''
       keepalive_timeout 10;                                
        '''
        print("Remediation : \nFind the HTTP or server block of your nginx configuration, and add the keepalive_timeout directive. Set it to 10 seconds or less, but not 0. This example command sets it to 10 seconds:\n" + example )    
    else:
        print("[+] Timeout is set to more than 10 seconds ")
        os.system(grep_command)               
        example = '''
       keepalive_timeout 10;                                
        '''
        print("Remediation : \nFind the HTTP or server block of your nginx configuration, and add the keepalive_timeout directive. Set it to 10 seconds or less, but not 0. This example command sets it to 10 seconds:\n" + example )    
  except subprocess.CalledProcessError :
       print("[+] Timeout is not set ")
       os.system(grep_command)               
       example = '''
       keepalive_timeout 10;                                
        '''
       print("Remediation : \nFind the HTTP or server block of your nginx configuration, and add the keepalive_timeout directive. Set it to 10 seconds or less, but not 0. This example command sets it to 10 seconds:\n" + example )     
  #grep -ir send_timeout /etc/nginx
def send_timeout():
  print("[+] Ensure send_timeout is 10 seconds or less, but not 0 ")
  try:
    grep_command = "grep -ir send_timeout /etc/nginx"
    output = subprocess.check_output(grep_command, shell=True, text=True)
# extract the number between 1-10 using regex
    number = re.findall(r"([1-9]|10)", output)[0]
    response_int = int(number)  
    if response_int <= 10:
        print("[+] Timeout is set to 10 seconds or less")
        os.system(grep_command)         
    elif response_int == 0:
        print("[-] Timeout is set to 0")
        os.system(grep_command)   
        example = '''
       send_timeout 10;                                
        '''
        print("Remediation : \nFind the HTTP or server block of your nginx configuration, and add the send_timeout  directive. Set it to 10 seconds or less, but not 0. This example command sets it to 10 seconds:\n" + example )    
    else:
        print("[+] Timeout is set to more than 10 seconds ")
        os.system(grep_command)               
        example = '''
       send_timeout 10;                                
        '''
        print("Remediation : \nFind the HTTP or server block of your nginx configuration, and add the send_timeout  directive. Set it to 10 seconds or less, but not 0. This example command sets it to 10 seconds:\n" + example )    
  except subprocess.CalledProcessError :
       print("[-] Timeout is not set ")
       os.system(grep_command)               
       example = '''
       send_timeout 10;                                
        '''
       print("Remediation : \nFind the HTTP or server block of your nginx configuration, and add the send_timeout directive. Set it to 10 seconds or less, but not 0. This example command sets it to 10 seconds:\n" + example )     
def server_tokens (url):
 print("[+] Ensure server_tokens directive is set to `off` ")
 try:
    curl_cmd = f"curl -I --silent {url}  | grep -i server "
    response = subprocess.check_output(curl_cmd, shell=True).decode().strip()
    if response:
        print("[-] Contains the server header providing the server version")
        os.system(curl_cmd)  
        example = ''' 
        server {
        ...
        server_tokens off;
        ...
        }
        '''
        print("Remediation : \nDisable the server_tokens directive, set it to off inside of every server block in your nginx.conf or in the http block:\n" + example )       
    else:
        print("[+] Doesn't contain the server header providing the server version ")
        os.system(curl_cmd)  
 except subprocess.CalledProcessError :
        print("[-] Doesn't contain the server header providing the server version ")
        os.system(curl_cmd)  
def error_html():
 print("[+] Ensure default error and index.html pages do not reference NGINX ")
 try:
    html_cmd = "grep -i nginx /usr/share/nginx/html/index.html "
    refer = subprocess.check_output(html_cmd, shell=True).decode().strip()

    if refer:
        print("[-] The html pages references nginx")
        os.system(html_cmd)  
        print("Remediation :\nEdit /usr/share/nginx/html/index.html and remove any lines that reference NGINX."  )       
    else:
        print("[+] The html pages does not reference nginx")
        os.system(html_cmd)  
 except subprocess.CalledProcessError :
        print("[-]  The html pages does not reference nginx ")
        os.system(html_cmd)  
def hidden_file ():
 print("[+] Ensure hidden file serving is disabled ")
   #grep -i '^\s*location\s+~\s*/\.[^{]*{\s*deny\s+all;\s*return\s+404;\s*}' /etc/nginx/nginx.conf
 try:
    hidden_cmd = "grep location /etc/nginx/nginx.conf "
    cmd = subprocess.check_output(hidden_cmd, shell=True).decode().strip()
    hidden = re.findall(r"^\s*location\s+~\s*/\.[^{]*{\s*deny\s+all;\s*return\s+404;\s*} ", cmd)
    if hidden:
        print("[+] The hidden file serving is disabled ")
        os.system(hidden_cmd)  
    else:
        print("[-] The hidden file serving is enabled")
        os.system(hidden_cmd)  
        example = ''' 
        location ~ /\. { 
        deny all;
        return 404;
        }
        '''
        print("Remediation : \nEdit the nginx.conf file and add the following line:\n" + example )       
 except subprocess.CalledProcessError :
        print("[-]  The hidden file serving does not exist")
        os.system(hidden_cmd)  
        example = ''' 
        location ~ /\. { 
        deny all;
        return 404;
        }
        '''
        print("Remediation : \nEdit the nginx.conf file and add the following line:\n" + example )    
def reverse_proxy():
    print("[+] Ensure the NGINX reverse proxy does not enable information disclosure ")
    # Use subprocess to execute the command
    grep_command = " grep proxy_hide_header /etc/nginx/nginx.conf | grep X-Powered-By "
    grep_command1 = "grep proxy_hide_header /etc/nginx/nginx.conf | grep  Server "
    try:
      x_power= subprocess.check_output(grep_command, shell=True).decode().strip()
      server = subprocess.check_output(grep_command1, shell=True).decode().strip()
      if not (x_power and server):
           print("[-] NGINX reverse proxy does not have X-Powered-By and Server set, as a result has enabled information disclosure ")
           os.system(grep_command)
           example = ''' 
           location /docs {
            ....
           proxy_hide_header X-Powered-By;
           proxy_hide_header Server;
           ....
           }

        '''
           print("Remediation : \nImplement the below directives as part of your location block. Edit /etc/nginx/nginx.conf and add the following:\n" + example )   
      else:
           print("[+] NGINX reverse proxy has X-Powered-By and Server set  ")   
           proxy = " grep proxy_hide_header /etc/nginx/nginx.conf"
           os.system(proxy)         
    except subprocess.CalledProcessError :
          print("[-] NGINX reverse  proxy does not have proxy_hide_header itself set")
          example = ''' 
           location /docs {
            ....
           proxy_hide_header X-Powered-By;
           proxy_hide_header Server;
           ....
           }

        '''
          print("Remediation : \nImplement the below directives as part of your location block. Edit /etc/nginx/nginx.conf and add the following:\n" + example )   
def access_log_enabled():
 print("[+] Ensure access logging is enabled")
 try:
    access_cmd = "grep -ir access_log /etc/nginx "
    cmd = subprocess.check_output(access_cmd, shell=True).decode().strip()
    access = re.findall(r"(off|OFF|Off)", cmd)
    if access:
        print("[-] Access logging is disabled ")
        os.system(access_cmd)  
        example = ''' 
      access_log /var/log/nginx/host.access.log main;
        '''
        print("Remediation : \nEnsure the access_log directive is configured for every core site your organization requires logging for.This should look similar to the below configuration snippet. \nYou may use different log file locations based on your needs:\n" + example )     
    else:
        print("[+] Access logging is enabled")
        os.system(access_cmd)    
 except subprocess.CalledProcessError :
        print("[-] Access Logging does not exist")
        os.system(access_cmd)  
        example = ''' 
      access_log /var/log/nginx/host.access.log main;
        '''
        print("Remediation : \nEnsure the access_log directive is configured for every core site your organization requires logging for.This should look similar to the below configuration snippet. \nYou may use different log file locations based on your needs:\n" + example )     
def error_log():
 print("[+] Ensure error logging is enabled and set to the info logging level ")
 try:
    error_cmd = "grep '^\s*[^#]*error_log.*info' /etc/nginx/nginx.conf "
    cmd = subprocess.check_output(error_cmd, shell=True).decode().strip()
    if cmd:
        print("[+] Error logging is enabled and set to the info logging level ")
        os.system(error_cmd)  

    else:
        print("[-] Error logging is not enabled and not set to the info logging level or commented out  ")
        example = ''' 
        error_log /var/log/nginx/error_log.log info;
        '''
        print("Remediation : \nEdit /etc/nginx/nginx.conf so the error_log directive is present and not commented out. The error_log should be configured to the logging location of your choice. \nThe configuration should look similar to the below\n" + example )       
 except subprocess.CalledProcessError :
        print("[-] Error logging is not enabled and not set to the info logging level or commented out  ")  
        example = ''' 
        error_log /var/log/nginx/error_log.log info;
        '''
        print("Remediation : \nEdit /etc/nginx/nginx.conf so the error_log directive is present and not commented out. The error_log should be configured to the logging location of your choice. \nThe configuration should look similar to the below\n" + example )       
def log_files():
 print("[+] Ensure log files are rotated ")
 try:
    log_cmd = "cat /etc/logrotate.d/nginx  "
    cmd = subprocess.check_output(log_cmd, shell=True).decode().strip()
    weekly = re.findall(r"weekly", cmd)
    if weekly:
        print("[+] Log compression occurs weekly")
        os.system(log_cmd)  

    else:
        print("[-] Log compression does not occur weekly ")
        os.system(log_cmd)  
        example = ''' 
    sed -i "s/daily/weekly/" /etc/logrotate.d/nginx
        '''
        print("Remediation : \nFollow the below procedure to change the default configuration to the recommended log rotation configuration. You may need to manually edit the /etc/logrotate.d/nginx file or change the below command if the configuration is not the default.\nTo change log compression from daily to weekly\n" + example )       
 except subprocess.CalledProcessError :
        print("[-] Log file does not exist")
        os.system(log_cmd)  
        example = ''' 
    sed -i "s/daily/weekly/" /etc/logrotate.d/nginx
        '''
        print("Remediation : \nEnsure that this file exists and follow the below procedure to change the default configuration to the recommended log rotation configuration. You may need to manually edit the /etc/logrotate.d/nginx file or change the below command if the configuration is not the default.\nTo change log compression from daily to weekly\n" + example )       
 try:
    log_cmd = "cat /etc/logrotate.d/nginx "
    cmd = subprocess.check_output(log_cmd, shell=True).decode().strip()
    rotate = re.findall(r"rotate\s+13", cmd)
    if rotate:
        print("[+] Log rotation happens every 13 weeks")
        os.system(log_cmd)  

    else:
        print("[-] Log rotation does not happen every 13 weeks ")
        example = ''' 
     sed -i "s/rotate {current setting}/rotate 13/" /etc/logrotate.d/nginx
        '''
        print("Remediation : \nTo change log rotation from your current setting to every 13 weeks: \n" + example )       
 except subprocess.CalledProcessError :
        print("[-] Log file does not exist")
        os.system(log_cmd)  
        example = ''' 
         sed -i "s/rotate {current setting}/rotate 13/" /etc/logrotate.d/nginx
        '''
        print("Remediation : \nCreate a log file and change log rotation from  your current setting to every 13 weeks: \n" + example )       
def error_log_syslog():
 print("[+] Ensure error logs are sent to a remote syslog server")
 try:
    log_cmd = "grep -ir syslog /etc/nginx  "
    cmd = subprocess.check_output(log_cmd, shell=True).decode().strip()
    ip_address = input('Enter the IP adddress of your syslog server : ')     
    pattern = r"error_log syslog:server=" + re.escape(ip_address) + r" info"
    matches = re.findall(pattern, cmd)
    if matches:
        print("[+] Error logs are  sent to a syslog server")
        os.system(log_cmd)  

    else:
        print("[-] Error logs are not being sent to a syslog server ")
        os.system(log_cmd)  
        example = ''' 
    error_log syslog:server={your_IP_Addr} info;
        '''
        print("Remediation : \nTo enable central logging for your error logs, add the below line to your server block in your server configuration file. \nAdd the IP Address of  your central log server.\n" + example )       
 except subprocess.CalledProcessError :
        print("[-] Error log directive does not exist")
        os.system(log_cmd)  
        example = ''' 
    error_log syslog:server={your_IP_Addr} info;
        '''
        print("Remediation : \nTo enable central logging for your error logs, add the below line to your server block in your server configuration file.\n Add the IP Address of  your central log server.\n" + example )       
def access_log_syslog():
 print("[+] Ensure access logs are sent to a remote syslog server ")
 try:
    log_cmd = "grep -ir syslog /etc/nginx  "
    cmd = subprocess.check_output(log_cmd, shell=True).decode().strip()
    ip_address = input('Enter the IP adddress of your syslog server : ')     
    pattern = r"access_log syslog:server=" + re.escape(ip_address) 
    matches = re.findall(pattern, cmd)
    if matches:
        print("[+] Access logs are sent to a syslog server")
        os.system(log_cmd)  

    else:
        print("[-] Access logs are not being sent to a syslog server ")
        os.system(log_cmd)  
        example = ''' 
    access_log syslog:server={your_IP_Addr},facility=local7,tag=nginx,severity=info 
    combined; 
        '''
        print("Remediation : \n To enable central logging for your access logs, add the below line to your server block in your server configuration file. 192.168.2.1 should be replaced with the location of your central log server. The local logging facility may be changed to any unconfigured facility on your server\n" + example )       
 except subprocess.CalledProcessError :
        print("[-] Access log directive does not exist")
        os.system(log_cmd)  
        example = ''' 
    access_log syslog:server={your_IP_Addr},facility=local7,tag=nginx,severity=info 
    combined; 
        '''
        print("Remediation : \n To enable central logging for your access logs, add the below line to your server block in your server configuration file. 192.168.2.1 should be replaced with the location of your central log server. The local logging facility may be changed to any unconfigured facility on your server\n" + example )       
  
def proxies():
 print("[+] Ensure proxies pass source IP information  ")
 try:
    log_cmd = "grep -ir proxy_set_header /etc/nginx  "
    cmd = subprocess.check_output(log_cmd, shell=True).decode().strip()  
    pattern = r"proxy_set_header\s+(X-Real-IP|X-Forwarded-For)\s+(\S+);"
    matches = re.findall(pattern, cmd)
    if matches:
        print("[+] The proxies pass source IP information")
        os.system(log_cmd)  

    else:
        print("[-] The proxies does not pass source IP information")
        os.system(log_cmd)  
        example = ''' 
server {
 ...
location / {
 proxy_pass (Insert Application URL here);
 proxy_set_header X-Real-IP $remote_addr;
 proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
 }
}
        '''
        print("Remediation : \n To ensure your proxy or load balancer will forward information about the client and the proxy to the application, you must set the below headers in your location block. Edit your location block so it shows the proxy_set_header directives for the client and the proxy as shown below. These headers are the exact same and there is no need to have both present.\n" + example )       
 except subprocess.CalledProcessError :
        print("[-] Proxy directive does not exist")
        os.system(log_cmd)  
        example = ''' 
server {
 ...
location / {
 proxy_pass (Insert Application URL here);
 proxy_set_header X-Real-IP $remote_addr;
 proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
 }
}
        '''
        print("Remediation : \n To ensure your proxy or load balancer will forward information about the client and the proxy to the application, you must set the below headers in your location block. Edit your location block so it shows the proxy_set_header directives for the client and the proxy as shown below. These headers are the exact same and there is no need to have both present.\n" + example )       
def proxies():
 print("[+] Ensure proxies pass source IP information  ")
 try:
    log_cmd = "grep -ir proxy_set_header /etc/nginx  "
    cmd = subprocess.check_output(log_cmd, shell=True).decode().strip()  
    pattern = r"proxy_set_header\s+(X-Real-IP|X-Forwarded-For)\s+(\S+);"
    matches = re.findall(pattern, cmd)
    if matches:
        print("[+] The proxies pass source IP information")
        os.system(log_cmd)  

    else:
        print("[-] The proxies does not pass source IP information")
        os.system(log_cmd)  
        example = ''' 
server {
 ...
location / {
 proxy_pass (Insert Application URL here);
 proxy_set_header X-Real-IP $remote_addr;
 proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
 }
}
        '''
        print("Remediation : \n To ensure your proxy or load balancer will forward information about the client and the proxy to the application, you must set the below headers in your location block. Edit your location block so it shows the proxy_set_header directives for the client and the proxy as shown below. These headers are the exact same and there is no need to have both present.\n" + example )       
 except subprocess.CalledProcessError :
        print("[-] Proxy directive does not exist")
        os.system(log_cmd)  
        example = ''' 
server {
 ...
location / {
 proxy_pass (Insert Application URL here);
 proxy_set_header X-Real-IP $remote_addr;
 proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
 }
}
        '''
        print("Remediation : \n To ensure your proxy or load balancer will forward information about the client and the proxy to the application, you must set the below headers in your location block. Edit your location block so it shows the proxy_set_header directives for the client and the proxy as shown below. These headers are the exact same and there is no need to have both present.\n" + example )       
def check_redirect(url):
    response = requests.get(url)

    if response.history:
        print("Request was redirected")

        for redirect in response.history:
            print(redirect.status_code, redirect.url)

        print("Final destination:")
        print(response.status_code, response.url)
    else:
        print("Request was not redirected")
        print(response.status_code, response.url)
if __name__ == '__main__':
  banner = '''
                  _          _                 __       _                  
                 (_)        / |_              [  |  _  / |_                
 _ .--.   .--./) __  _ .--.`| |-'_ .--.  ,--.  | | / ]`| |-' .--.  _ .--.  
[ `.-. | / /'`\;[  |[ `.-. || | [ `/'`\]`'_\ : | '' <  | | / .'`\ [ `/'`\] 
 | | | | \ \._// | | | | | || |, | |    // | |,| |`\ \ | |,| \__. || |     
[___||__].',__` [___|___||__]__/[___]   \'-;__[__|  \_]\__/ '.__.'[___]    
        ( ( __))                                                           
'''

  if len(sys.argv) != 2:
    print(f"{Fore.WHITE}Usage: python3 nginxtraktor.py https://example.com ")
    sys.exit()
  if sys.argv[1].endswith("/"):
     print(f"{Fore.WHITE}[?] Please provide the URL without slash at the end")
     sys.exit()

  url = sys.argv[1]
  basereq = requests.get(url, verify=False)
  print(Fore.RED+banner)
   # check_nginx_installed()
    #installed_from_source()
  account_security()
  directories_perms()
  secure_pid()
  block_ips()
  crlf_injections()
  curl_host(url)
  keepalive_timeout()
  send_timeout()
  server_tokens (url)
  error_html()
  reverse_proxy()
  access_log_enabled()
  error_log()
  error_log_syslog()
  access_log_syslog()
  proxies()
    #https://chat.openai.com/chat/64b0c52c-01db-4523-aae7-e9bcdce77f40