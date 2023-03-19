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
import random
import string
import uuid

def check_nginx_installed():
    print ("[+] Check the nginx version installed currently")
    # run the nginx -v command and use grep to extract the version number
    grep_command = "nginx -v 2>&1 | grep -Po '(?<=nginx/)[0-9]+.[0-9]+.[0-9]+'"
    nginx_version = subprocess.check_output(grep_command, shell=True).decode().strip()
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
            remediate = input("Do you want to update NGINX to the latest version? (y/n) ")
            if remediate.lower() == "y":
                # install_nginx = "git clone https://github.com/nginx/nginx.git"
                # subprocess.run(install_nginx, shell=True)
                subprocess.run(['sudo', 'apt-get', 'update'])
                subprocess.run(['sudo', 'apt-get', 'install', 'nginx'])
                print("[+] NGINX has been updated to the latest version")

            
            elif remediate.lower() == "n":
                print("[+] NGINX has not been updated to the latest version")

            
            else:
                print(f"{Fore.RED} NGINX has not been updated")

        else:
            print(f"[+] NGINX version is up to date")

    else:
        print(f"{Fore.RED}[-]Unable to determine nginx version")

def installed_from_source():
    print("[+] Check if nginx is installed from source")
    grep_command = "nginx -v 2>&1 | grep -Po '(?<=nginx/)[0-9]+.[0-9]+.[0-9]+'"
    installed_from_source = subprocess.check_output(grep_command, shell=True).decode().strip()
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
                modules = input("Add the modules u want to implement in the web server ")
                configure_command = f"./configure {modules}"
                os.system(configure_command)
                make_command = "make"
                os.system(make_command)
                make_install_command = "make install"
                os.system(make_install_command)
                print("[+] NGINX has been updated to the latest version")
            elif remediate.lower() == "n":
                print(f"{Fore.RED}[-] NGINX has not been updated to the latest version")
            else:
                print(f"{Fore.RED}[-] NGINX has not been updated")
        else:
            print(f"{Fore.RED}[-] NGINX version is up to date")
    else:
        print("NGINX is not installed from source.")
    
    # Get the current version number from nginx -v
    grep_command = "nginx -v 2>&1 | grep -Po '(?<=nginx/)[0-9]+.[0-9]+.[0-9]+'"
    nginx_version = subprocess.check_output(grep_command, shell=True).decode().strip()
def check_url_directory_listing(url):
    response = requests.get(url,allow_redirects=False)
    if "Index of" in response.text:
        print("[-] Directory listing enabled")
    else:
        print(f"{Fore.RED} [-] Directory listing disabled")
    
# Audit for http_dav_module
def audit_http_dav_module():
    command = 'nginx -V 2>&1 | grep http_dav_module'
    output = subprocess.check_output(command, shell=True).decode(sys.stdout.encoding).strip()
    if output:
        print(f'{Fore.RED}[-] http_dav_module is installed')
    else:
        print('[+] http_dav_module is not installed')

# Audit for gzip modules
def audit_gzip_modules():
    command = 'nginx -V 2>&1 | grep -E "(http_gzip_module|http_gzip_static_module)"'
    output = subprocess.check_output(command, shell=True).decode(sys.stdout.encoding).strip()
    if output:
        print(f'{Fore.RED}[-] gzip modules are installed')
    else:
        print('[+] gzip modules are not installed')    
def account_security():
    print("[+] Ensure that NGINX is run using a non-privileged, dedicated service account and check whether the service accounts are locked")
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
                print(f"{Fore.RED}[-] The nginx dedicated user {user} is part of any unexpected groups")
             else:
                print(f'{Fore.RED}[-]No nginx group found')
                print('[-] Make sure that a dedicated group directive present in the {} file\n'.format(nginx_configfile))
          else:
            print(f"{Fore.RED}[-] A dedicated nginx user called {user} is privileged")        
       elif user == nginx :
          print(f"[+] A dedicated nginx user called {user} exists")
          priv_command = "sudo -l -U {} |  grep -io 'not allowed to run sudo'".format(user)
          get_priv = subprocess.check_output(priv_command, shell=True).decode().strip()
          if get_priv:
             print(f"{Fore.RED}[-] A dedicated nginx user called {user} is not privileged")
             grp_command = f"groups {user}  | grep -io '{user} : {user}' "
             get_grp = subprocess.check_output(grp_command, shell=True).decode().strip()
             if get_grp:
                print(f"[+] The nginx dedicated user {user} is not part of any unexpected groups")
             elif not get_grp:
                print(f"{Fore.RED}[-] The nginx dedicated user {user} is part of any unexpected groups")
             else:
                print(f'{Fore.RED}[-] No nginx group found')
                print('[-] Make sure that a dedicated group directive present in the {} file\n'.format(nginx_configfile))
          else:
            print(f"{Fore.RED}[-] A dedicated nginx user called {user} is  privileged")                   
       else:
          print(f"{Fore.RED}[-] {user} is not a dedicated user")      
    elif not get_acc:
       print(f'{Fore.RED}[-] A dedicated nginx user does not exist')
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
           print(f"{Fore.RED}[-] A system account is not added for the nginx user")
       else:
           print(f"{Fore.RED}[-] Something wrong has occured")
    else:
      print('[-] A dedicated nginx user does not exist')   

# Ensure Nginx User is Locked
    if os.popen('passwd -S {}'.format(user)).read().split()[1] != 'L':
       print(f'{Fore.RED}[-] The nginx user should be locked') 
       remediate = input("Do you want to fix this issue? (y/n) ")
       
       if remediate.lower() == "y":   
          grep_command = f"passwd -l {user}"
          os.system(grep_command)
       elif remediate.lower() == "n":
          print(f'{Fore.RED}[-]The nginx user is not locked')          
    else:
       print('[+] The nginx user is not locked') 
# Ensure Nginx User Account has Invalid Shell
    if not os.popen("grep {} /etc/passwd | grep -io '/sbin/nologin'".format(user)).read():
       print(f'{Fore.RED}[-] Nginx user should not have an invalid login shell')
       remediate = input("Do you want to fix this issue? (y/n) ")
       if remediate.lower() == "y":   
          grep_command = f"usermod -s /sbin/nologin {user}"
          os.system(grep_command)
       elif remediate.lower() == "n":
          print(f'{Fore.RED} [-] The nginx user still has an invalid login shell')            
    else:
       print('[+] The nginx user does not have an invalid login shell')         
       grep_command = f"usermod -s /sbin/nologin {user}"
       os.system(grep_command)
       
def directories_perms():
    print("[+] Check the permissions of the /etc/nginx directory")
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
          print(f"{Fore.RED}[-] The {configDir} directory's uid is still not root ")          
    elif not gid_root:
        remediate = input("Do you want to fix this issue? (y/n) ")
        if remediate.lower() == "y":   
          grep_command = f"chown -R root:root {configDir}"
          os.system(grep_command)
          print(f"[+] The {configDir} directory's gid is changed to root ")            
        elif remediate.lower() == "n":
          print(f"{Fore.RED}[-]The {configDir} directory's gid is still not root ")   
    else:
        print(f"[+] The {configDir} directory's gid and uid is set to root ")   
        grep_command = f" stat {configDir} "
        os.system(grep_command)           
def restricted_perms():
    print("[+] Ensure access to NGINX directories and files is restricted")
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
          print(f"{Fore.RED}[-] Permissions are not set with the ability to read as other by default on the configuration directory {configDir}: -rw-r--r-- ")     
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
               print(f"{Fore.RED}[-]Permissions are not set with the ability to read as other by default on the configuration directory {path1}: -rw-r--r-- ")
                 
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
                print(f"{Fore.RED}[-] Cannot permissions for the files : {e}")
                grep_command = "sudo find /etc/nginx -type d -exec stat -Lc '%n %a'{} + "
                os.system(grep_command)
      
    try:
        grep_command3 = "sudo find /etc/nginx -type f -printf '%m\n'"
        file_perm_output = subprocess.check_output(grep_command3, shell=True).decode().strip()
        file_perms = file_perm_output.split('\n')
        remediate = False
        for perm in file_perms:
            perm_int = int(perm)
            if not perm_int <= 660:
                remediate = True
                break
        if remediate:
            remediate_input = input("Do you want to fix this issue? (y/n) ")
            if remediate_input.lower() == "y":
                grep_command = "sudo find /etc/nginx -type f -exec chmod ug-x,o-rwx {} +"
                os.system(grep_command)
                print(f"[+] Permissions are set to restrict access to NGINX directory files: -rw-rw----")
            else:
                print(f"{Fore.RED}[-] Permissions are set with the ability to read and execute as other by default on directory file : -rw-rw-r--")
        else:
            print(f"[+] Access to NGINX directory is restricted: -rw-rw----")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[-] Some files don't exist")
        grep_command3 = "sudo find /etc/nginx -type f -exec stat -Lc '%n %a' {} +"
        os.system(grep_command3)
def core_dump():
  print("[+]  Ensure the core dump directory is secured")
  # Set the nginx configuration file path
  nginx_conf = "/etc/nginx/nginx.conf"

  #Check if the working_directory directive is configured in nginx.conf
  with open(nginx_conf, "r") as f:
    nginx_conf_content = f.read()
  if "working_directory" in nginx_conf_content:
    # Get the value of the working_directory directive
    working_directory_value = nginx_conf_content.split("working_directory")[1].split(";")[0].strip()
    # Verify if the working_directory meets the requirements
    if os.path.realpath(working_directory_value).startswith("/var/www"):
        print(f"{Fore.RED}[-] The working_directory is within the NGINX web document root, which is not secure.")
    elif os.stat(working_directory_value).st_uid != 0:
        print(f"{Fore.RED}[-] The working_directory is not owned by root, which is not secure.")
    elif os.stat(working_directory_value).st_gid != 33:
        print(f"{Fore.RED}[-] The working_directory does not have the NGINX group ownership, which is not secure.")
    elif os.stat(working_directory_value).st_mode & 0o777 != 0o750:
        print(f"{Fore.RED}[-] The working_directory has read-write-search access permission for other users, which is not secure.")
    else:
        print("[+] The working_directory configuration is secure.")
  else:
    print(f"{Fore.RED}[-] The working_directory directive is not configured in nginx.conf.")                

def secure_pid():
    print("Ensure the NGINX process ID (PID) file is secured")
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
          print(f"{Fore.RED}[-] The PID file {nginx_configfile} is still not owned by root ")           

    elif not perm_int >= 644 :
          print(f"{Fore.RED}[-] The PID file {nginx_configfile}'s permissions is not set to 644 ")    
          remediate = input("Do you want to fix this issue? (y/n) ")
          if remediate.lower() == "y":   
           grep_command = f" chmod u-x,go-wx  {nginx_configfile}  "
           os.system(grep_command)
           print(f"[+] The PID file {nginx_configfile}'s permissions is now set correctly ")     
          elif remediate.lower() == "n":
           print(f"{Fore.RED}[-] The PID file {nginx_configfile}'s permissions is still not set correctly   ")              
               
    else:
           print("[+] The PID file's ownership and permissions are set correctly")
           grep_command3 = f"stat -L -c '%U:%G' {nginx_configfile} && stat -L -c '%a' {nginx_configfile}"
           os.system(grep_command3)



def block_ips():
  print("[+] Block IP addresses that have tried to conduct malicious injections of the web server's URL ")
  access_log_path = r'/var/log/nginx/access.log'
  payload = r'payloads.txt'
  nginxfolderDir = r'/etc/nginx/conf.d/'
  if not os.path.isdir(nginxfolderDir):
        nginxfolderDir = input('Enter the location of the config folder for nginx: ')
  blockips_conf_path = r'{}blockips.conf'.format(nginxfolderDir)
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
  # Block IP addresses using ngx_http_geo_module
  def block_ips(ip_set):
        if not ip_set:
           print("[+] No IP addresses connected to the web server performing malicious injections ")
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
  
        
def network_conn():
    print("[+] Check whether NGINX only listens for network connections on authorized ports  ")
    # Use subprocess to execute the command
    grep_command = "find /etc/nginx -type f,d -not -path '/etc/nginx/*' -exec grep -rE 'listen[^;]*;' {} + | grep -E '80' "
    grep_command1 = "find /etc/nginx -type f,d -not -path '/etc/nginx/*' -exec grep -rE 'listen[^;]*;' {} + | grep -E '443' "
    try:
      listen_net= subprocess.check_output(grep_command, shell=True).decode().strip()
      if not (listen_net):
           print(f"{Fore.RED}[-]  NGINX does not listen to authorized ports like 80")
           os.system(grep_command)
      elif (listen_net  )  is None :
           print(f"{Fore.RED}[-] NGINX does not listen to any ports   ")
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
           print(f"{Fore.RED}[-]  NGINX does not listen to authorized ports like 443")
           print("Remediation : Comment out or delete the associated configuration for that listener")
           os.system(grep_command1)
      elif (listen_net  )  is None :
           print(f"{Fore.RED}[-] NGINX does not listen to any ports  ")
           os.system(grep_command1)
      else:
           print("[+] NGINX only listens for network connections on authorized ports like 443  ")   
           os.system(grep_command1)         
    except subprocess.CalledProcessError as e:
                print(f"{Fore.RED}[-] Unable to check for connections as the some files in the /etc/nginx  directory don't have listners,thus check manually for those files ")
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
           print(f"{Fore.RED}[-] NGINX does not listen to any ports   ")
           os.system(grep_command1)
      else:
           print("[+] NGINX only listens for network connections on authorized ports like 80  ")   
           os.system(grep_command1)         
    except subprocess.CalledProcessError as e:
                print(f"{Fore.RED}[-] Unable to check for connections as the some files in the conf.d directory don't have listners, thus check manually for those files ")
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
           print(f"{Fore.RED}[-] NGINX does not listen to any ports ")
           os.system(grep_command1)
      else:
           print(f"{Fore.RED}[-]NGINX only listens for network connections on authorized ports like 443  ")   
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
        print(f"{Fore.RED}[-] Requests for unknown host names are not being rejected")
        print(f"HTTP response code: {response_int}")
        example = '''
        server {
          return 404;
            }
        '''
        print("Remediation : \nEnsure your first server block mirrors the below in your nginx configuration, either at /etc/nginx/nginx.conf or any included file within your nginx config:\n" + example )    
  except subprocess.CalledProcessError :
    print(f"{Fore.RED}[-] Requests for unknown host names are not being rejected")
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
        print(f"{Fore.RED}[-] Timeout is set to 0")
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
       print(f"{Fore.RED}[-] Timeout is not set ")
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
        print(f"{Fore.RED}[-] Timeout is set to 0")
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
        print(f"{Fore.RED}[-] Contains the server header providing the server version")
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
        print(f"{Fore.RED}[-] Doesn't contain the server header providing the server version ")
        os.system(curl_cmd)  
def error_html():
 print("[+] Ensure default error and index.html pages do not reference NGINX ")
 try:
    html_cmd = "grep -i nginx /usr/share/nginx/html/index.html "
    refer = subprocess.check_output(html_cmd, shell=True).decode().strip()

    if refer:
        print(f"{Fore.RED}[-] The html pages references nginx")
        os.system(html_cmd)  
        print("Remediation :\nEdit /usr/share/nginx/html/index.html and remove any lines that reference NGINX."  )       
    else:
        print("[+] The html pages does not reference nginx")
        os.system(html_cmd)  
 except subprocess.CalledProcessError :
        print(f"{Fore.RED}[-]  The html pages does not reference nginx ")
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
        print(f"{Fore.RED}[-] The hidden file serving does not exist")
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
           print(f"{Fore.RED}[-] NGINX reverse proxy does not have X-Powered-By and Server set, as a result has enabled information disclosure ")
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
           print(f"[-] NGINX reverse proxy has X-Powered-By and Server set  ")   
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
    access = re.findall(r"access_log\s+.*?\s+(?:on|ON)\b", cmd, re.IGNORECASE)

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
        print(f"{Fore.RED}[-] Error logging is not enabled and not set to the info logging level or commented out  ")
        example = ''' 
        error_log /var/log/nginx/error_log.log info;
        '''
        print("Remediation : \nEdit /etc/nginx/nginx.conf so the error_log directive is present and not commented out. The error_log should be configured to the logging location of your choice. \nThe configuration should look similar to the below\n" + example )       
 except subprocess.CalledProcessError :
        print(f"{Fore.RED}[-] Error logging is not enabled and not set to the info logging level or commented out  ")  
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
        print(f"{Fore.RED}[-] Log rotation does not happen every 13 weeks ")
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
    pattern =  r"(#?\s*error_log syslog:server=" + re.escape(ip_address) + r" info)"
    matches = re.findall(pattern, cmd)
    if matches:
        print("[+] Error logs are  sent to a syslog server")
        os.system(log_cmd)  

    else:
        print(f"{Fore.RED}[-] Error logs are not being sent to a syslog server ")
        os.system(log_cmd)  
        example = ''' 
    error_log syslog:server={your_IP_Addr} info;
        '''
        print("Remediation : \nTo enable central logging for your error logs, add the below line to your server block in your server configuration file. \nAdd the IP Address of  your central log server.\n" + example )       
 except subprocess.CalledProcessError :
        print(f"{Fore.RED}[-]Error log directive does not exist")
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
    pattern = r"(?<!#)\s*access_log\s+syslog:server=" + re.escape(ip_address)
    matches = re.findall(pattern, cmd)
    if matches:
        print("[+] Access logs are sent to a syslog server")
        os.system(log_cmd)  

    else:
        print(f"{Fore.RED}[-] Access logs are not being sent to a syslog server ")
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
    pattern = r"(?<!#)\s*proxy_set_header\s+(X-Real-IP|X-Forwarded-For)\s+(\S+);"
    matches = re.findall(pattern, cmd)
    if matches:
        print("[+] The proxies pass source IP information")
        os.system(log_cmd)  

    else:
        print(f"{Fore.RED}[-] The proxies does not pass source IP information")
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
        print(f"{Fore.RED}[-] Proxy directive does not exist")
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
def check_redirect():
    print("[+] Ensure HTTP is redirected to HTTPS ")
    url= input('Enter the HTTP version of your web server address : ') 
    response = requests.get(url)

    if response.history:
        print("[+] Request was redirected")

        for redirect in response.history:
            print(redirect.status_code, redirect.url)

        print("[+] Final destination:")
        print(response.status_code, response.url)
    else:
        print(F"{Fore.RED}[-] Request was not redirected")
        print(response.status_code, response.url)
        example = ''' 
server {
 listen 80;
 server_name cisecurity.org;
 return 301 https://$host$request_uri;
}

        '''
        print("Remediation : \n Edit your web server or proxy configuration file to redirect all unencrypted listening ports, such as port 80, using a redirection through the return directive (cisecurity.org is used as an example server name).\n" + example )       
def trust_chain_key():
 print("[+] Ensure a trusted certificate and trust chain is installed  ")
 try:
    log_cmd = " grep -ir ssl_certificate /etc/nginx/ "
    cmd = subprocess.check_output(log_cmd, shell=True).decode().strip()  
    pattern = r"^\s*([^#].*ssl_certificate(_key)?;)"
    matches = re.findall(pattern, cmd)
    cert_addr = input('Enter the file location of ssl_certificate directive (/etc/nginx/cert.pem) : ')     
    cert = f" cat  {cert_addr}"
    cert_cmd = subprocess.check_output(cert, shell=True).decode().strip()  
    pattern1 = r"(?s)-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----"
    cert_pattern= re.findall(pattern1, cert_cmd)
    if matches and cert_pattern:
        print("[+] A trusted certificate and trust chain is installed")
        os.system(log_cmd)  

    elif not cert_pattern:
        print(f"{Fore.RED}[-] The perm file in the configuration is empty ")
        remediate = input("Do you want to insatll a certificate and its signing certificate chain ? (y/n) ")
        if remediate.lower() == "y":
               cert_name = input('Enter the ssl certificate key name(nginx.key): ')     
               cert_bit = input(' Enter bit key stength (2048): ')    
               grep_command = f"openssl req -new -newkey rsa:{cert_bit}-keyout {cert_name} -out nginx.csr"
               os.system(grep_command)
               example = ''' 
server {
 listen 443 ssl http2;
 listen [::]:443 ssl http2;
 ssl_certificate /etc/nginx/cert.crt;
 ssl_certificate_key /etc/nginx/nginx.key;
 ...
 }


        '''
               print(f"[+] After creating the server's private key and a certificate signing request , obtain a signed certificate from your certificate authority and install the certificate and signing certificate chain on your web server and restart nginx by using the following example.\n " + example)
        elif remediate.lower() == "n":
               print(f"[-] Permissions are set with the ability to read and execute as other by default on directory file : drwxr-xr-x ")
        os.system(log_cmd)  
    elif not (matches and cert_pattern):
       print(f"{Fore.RED}[-] The trusted certificate and trust chain is not installed and the perm file is empty ")
       remediate = input("Do you want to insatll a certificate and its signing certificate chain ? (y/n) ")
       if remediate.lower() == "y":
               cert_name = input('Enter the ssl certificate key name(nginx.key): ')     
               cert_bit = input(' Enter bit key stength (2048): ')    
               grep_command = f"openssl req -new -newkey rsa:{cert_bit}-keyout {cert_name} -out nginx.csr"
               os.system(grep_command)
               example = ''' 
server {
 listen 443 ssl http2;
 listen [::]:443 ssl http2;
 ssl_certificate /etc/nginx/cert.crt;
 ssl_certificate_key /etc/nginx/nginx.key;
 ...
 }


        '''
               print(f"[+] After creating the server's private key and a certificate signing request , obtain a signed certificate from your certificate authority and install the certificate and signing certificate chain on your web server and restart nginx by using the following example.\n " + example)
       elif remediate.lower() == "n":
               print(f"{Fore.RED}[-] Permissions are set with the ability to read and execute as other by default on directory file : drwxr-xr-x ")
               os.system(log_cmd)          
    elif not matches:
       print(f"{Fore.RED}[-] The trusted certificate and trust chain is not installed ")
       remediate = input("Do you want to insatll a certificate and its signing certificate chain ? (y/n) ")
       if remediate.lower() == "y":
               cert_name = input('Enter the ssl certificate key name(nginx.key): ')     
               cert_bit = input(' Enter bit key stength (2048): ')    
               grep_command = f"openssl req -new -newkey rsa:{cert_bit}-keyout {cert_name} -out nginx.csr"
               os.system(grep_command)
               example = ''' 
server {
 listen 443 ssl http2;
 listen [::]:443 ssl http2;
 ssl_certificate /etc/nginx/cert.crt;
 ssl_certificate_key /etc/nginx/nginx.key;
 ...
 }


        '''
               print(f"[+] After creating the server's private key and a certificate signing request , obtain a signed certificate from your certificate authority and install the certificate and signing certificate chain on your web server and restart nginx by using the following example.\n " + example)
       elif remediate.lower() == "n":
               print(f"{Fore.RED}[-] Permissions are set with the ability to read and execute as other by default on directory file : drwxr-xr-x ")
               os.system(log_cmd)       
 except subprocess.CalledProcessError :
        print("[-]  A trusted certificate and trust chain does not exist")
def private_key_perm():
  print("[+] Ensure private key permissions are restricted  ")
  grep_command3 = "sudo find /etc/nginx/ -name '*.key' -exec stat -Lc ' %a' {} + "
  try:
        # Check if any .key files exist
        find_command = "sudo find /etc/nginx/ -name '*.key'"
        find_output = subprocess.check_output(find_command, shell=True)
        if not find_output:
            print(f"{Fore.RED}[-] No private key files found")
            return
        grep_command3 = "sudo find /etc/nginx/ -name '*.key' -exec stat -Lc ' %a' {} + "
        file_perm = subprocess.check_output(grep_command3, shell=True).decode().strip()
        file_perm_int = int(file_perm)  
        if not file_perm_int <= 400:
           remediate = input("Do you want to fix this issue? (y/n) ")
           if remediate.lower() == "y":
                grep_command = "sudo find /etc/nginx/ -name '*.key' -exec chmod u-wx,go-rwx {} + "
                os.system(grep_command)
                print(f"[+] Permissions of the private key file is set to 400 or below")
           elif remediate.lower() == "n":
                print(f"{Fore.RED}[-] Permissions of the private key file is not set to 400 or below ")
 
        else:
               print(f"[-] Private key file  permissions are restricted")
               grep_command3 = "sudo find /etc/nginx/ -name '*.key' -exec stat -Lc ' %a' {} +"
               os.system(grep_command3)                                    
  except subprocess.CalledProcessError :
               print(f"{Fore.RED}[-] Private key does not exist")
               grep_command3 = "sudo find /etc/nginx/ -name '*.key' -exec stat -Lc ' %a' {} + "
               os.system(grep_command3)   
def TLS():
 print("[+] Ensure only modern TLS protocols are used  ")
 try:
# Define regex pattern to match SSL protocols
    find_command = "grep -ir ssl_protocol /etc/nginx"
    pattern = r"ssl_protocols.*TLSv1\.2.*TLSv1\.3 "

# Get the Nginx configuration file
    config = subprocess.check_output(find_command, shell=True).decode().strip()

# Find all matches of the pattern in the configuration file
    matches = re.findall(pattern, config)
    if matches :
        print("[+] Only modern TLS protocols are used ")
        os.system(find_command)  

    elif not matches:
        print(f"{Fore.RED}[-] Older TLS protocols are being used ")
        remediate = input("Do you change SSL protocols configurations (y/n) ")
        if remediate.lower() == "y":
               type = input('Web Server or Proxy? (web/proxy): ')     
               if type.lower() == "web":
                  grep_command = "sed -i 's/ssl_protocols[^;]*;/ssl_protocols TLSv1.2 TLSv1.3;/'' /etc/nginx/nginx.conf"
                  os.system(grep_command)
               elif type.lower() == "proxy":
                  grep_command = "sed -i 's/proxy_ssl_protocols[^;]*;/proxy_ssl_protocols TLSv1.2 TLSv1.3;/' /etc/nginx/nginx.conf"
                  os.system(grep_command)
               print(f"[+] After creating the server's private key and a certificate signing request , obtain a signed certificate from your certificate authority and install the certificate and signing certificate chain on your web server and restart nginx by using the following example.\n " + example)
        elif remediate.lower() == "n":
               print(f"{Fore.RED}[-]  SSL protocols configurations  are not changed ")

       
 except subprocess.CalledProcessError :
        print("[-] The SSL protocol directive does not exist")
def weak_ciphers():
 print("[+] Disable weak ciphers ")
    # Search for ssl_ciphers and proxy_ssl_ciphers in /etc/nginx directory
 result = subprocess.run(["grep", "-ir", "ssl_ciphers\|proxy_ssl_ciphers", "/etc/nginx/"], stdout=subprocess.PIPE)
 output = result.stdout.decode()

    # Check if either ssl_ciphers or proxy_ssl_ciphers contain the cipher string
 regex = re.compile(r'.*ALL:!EXP:!NULL:!ADH:!LOW:!SSLv2:!SSLv3:!MD5:!RC4;.*')
 if regex.search(output):
        # Check if the cipher string is commented or not
    regex_commented = re.compile(r'^\s*#\s*(ssl_ciphers|proxy_ssl_ciphers)\s.*$|^(\s*ssl_ciphers|proxy_ssl_ciphers)\s.*')
    if regex_commented.search(output):
            print("[-] Cipher string found in nginx config file, but it is commented.")
            example = ''' 

server {
 ssl_ciphers ALL:!EXP:!NULL:!ADH:!LOW:!SSLv2:!SSLv3:!MD5:!RC4;

}
        '''
            example1 = ''' 

location / {
 proxy_pass https://cisecurity.org;
 proxy_ssl_ciphers ALL:!EXP:!NULL:!ADH:!LOW:!SSLv2:!SSLv3:!MD5:!RC4;
}

        '''
            print(f"[+] Remediation:\n After creating the server's private key and a certificate signing request , obtain a signed certificate from your certificate authority and install the certificate and signing certificate chain on your web server and restart nginx by using the following example.\n " + example +"\n" +example1)
    else:
            print(f"{Fore.RED}[-] Cipher string found in nginx config file.")
 else:
        print(f"{Fore.RED}[-] Cipher string not found in nginx config file.")
 
def ssl_dhparam():
 try:
    # Define regex pattern to match SSL protocols
    find_command = "grep ssl_dhparam /etc/nginx/nginx.conf"

# Get the Nginx configuration file
    config = subprocess.check_output(find_command, shell=True).decode().strip()

    regex = r'^\s*(#*\s*)ssl_dhparam\s+(.+);'

    match = re.findall(regex, config)

    if match:
        print("[+] ssl_dhparam is present in the nginx config file")
        print(config)
    elif not match:
        print("[+] ssl_dhparam is commented out")
        print(config)       
    else:
        print("[+] ssl_dhparam is present and the path to the file is")
 except subprocess.CalledProcessError:
        print(f"{Fore.RED}[-] ssl_dhparam is not present in the config file")
        remediate = input(" Want to generate strong DHE (Ephemeral Diffie-Hellman) parameters(y/n) ")
        if remediate.lower() == "y":
                  grep_command = "mkdir /etc/nginx/ssl"
                  os.system(grep_command)
                  grep_command1= "openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048"
                  os.system(grep_command1)
                  grep_command2= "chmod 400 /etc/nginx/ssl/dhparam.pem"
                  os.system(grep_command2)
                  example = '''
                 http {
 server {
 ssl_dhparam /etc/nginx/ssl/dhparam.pem;
 }
}
                  '''
                  print("Alter the  server configuration to use the new parameters by doing the following:\n" + example)   
        elif remediate.lower() == "n":
                print(f"{Fore.RED}[-]  Configurations for ssl_dhparam are not being changed ")

def crlf_injections(url):
    payload = "/static/%0d%0aX-Foo:%20CLRF"


    crlf_req = requests.get(url  + payload, verify=False,allow_redirects=False)

    if "X-FOO" in crlf_req.headers :
        print(f"{Fore.RED}[-] CRLF injection vulnerability found as configuration in this web server uses $uri or $document_uri instead of $request_uri:", payload)
        print("Remediation: Check your configurations files for $uri or $document_uri and remove those lines or use the $request_uri instead" )
    else:
        print(f"[-] No CRLF injection vulnerability with payload:", payload)
        print(crlf_req)
        
def OCSP():
 print("[+]  Ensure Online Certificate Status Protocol (OCSP) stapling is enabled")
 try:
    ocsp_cmd = "grep -ir ssl_stapling /etc/nginx "
    cmd = subprocess.check_output(ocsp_cmd, shell=True).decode().strip()
    ocsp = re.findall(r"ssl_stapling\s+.*?\s+(?:on|ON)\b", cmd, re.IGNORECASE)

    if not ocsp:
        print(f"{Fore.RED}[-] OCSP is disabled ")
        os.system(ocsp_cmd)  
        example = ''' 
server {
 ssl_stapling on;
 ssl_stapling_verify on;
}
        '''
        print("Remediation : \nEnsure your NGINX server has access to your CA's OCSP server and enable it on nginx by doing the following:\n" + example )     
    else:
        print("[+] OCSP is enabled")
        os.system(ocsp_cmd)    
 except subprocess.CalledProcessError :
        print(f"{Fore.RED}[-] OCSP does not exist")
        os.system(ocsp_cmd)  
        example = ''' 
     server {
 ssl_stapling on;
 ssl_stapling_verify on;
}
        '''
        print("Remediation : \nEnsure your NGINX server has access to your CA's OCSP server and enable it on nginx by doing the following:\n" + example )     
def HSTS():
   print("[+] Ensure  HTTP Strict Transport Security (HSTS) is enabled and the domain is preloaded  ")
   # Look for the Strict-Transport-Security header in all Nginx config files
   cmd_output = os.popen("grep -ir 'Strict-Transport-Security' /etc/nginx").read()

    # Check if the expected header is found
   if 'add_header Strict-Transport-Security "max-age=15768000;" always;' in cmd_output:
        print("[+] The Strict-Transport-Security header with the appropriate max-age value is set.")
   else:
        print("[-] The Strict-Transport-Security header with the appropriate max-age value is not set.")
        print("Remediation:Add the header in nginx config file in this way:\nadd_header Strict-Transport-Security ' maxage=31536000; includeSubDomains;' preload;")
def proxy_ssl():
 print("[+] Ensure upstream server traffic is authenticated with a client certificate  ")
 try:
    cert_cmd = " grep -ir proxy_ssl_certificate /etc/nginx | grep -E '^[^#]*proxy_ssl_certificate\s+\/etc\/nginx\/ssl\/nginx\.pem;'"
    cert_cmd1 = " grep -ir proxy_ssl_certificate /etc/nginx | grep -E '^[^#]*proxy_ssl_certificate_key\s+\/etc\/nginx\/ssl\/nginx\.key;'"
    cmd = subprocess.check_output(cert_cmd, shell=True).decode().strip()  
    cmd1 = subprocess.check_output(cert_cmd1, shell=True).decode().strip()  
    if cmd and cmd1:
        print("[+] The client certificate validation directive is set successfully")
        os.system(cert_cmd)  
        os.system(cert_cmd1)  

    elif not (cmd and cmd1):
        print("[-] The client certificate validation directive is set successfully ")
        os.system(cert_cmd) 
        os.system(cert_cmd1) 
        example = ''' 
proxy_ssl_certificate /etc/nginx/ssl/nginx.pem; 
proxy_ssl_certificate_key /etc/nginx/ssl/nginx.key;

        '''
        print("Remediation : \nCreate a client certificate to be authenticated against and have it signed. Once you have a signed certificate, place the certificate in a location of your choice. In the below example, we use /etc/nginx/ssl/cert.pem. Implement the configuration as part of the location block:\n" + example )      
 except subprocess.CalledProcessError :
        print("[-]  Both client certificate validation directives or one of the directive does not exist")
def trusted_cert():
 print("[+]   Ensure the upstream traffic server certificate is trusted ")
 try:
    cert_cmd = "  grep -irE '^[^#]*proxy_ssl_trusted_certificate\s+/etc/nginx/trusted_ca_cert.crt;' /etc/nginx"
    cert_cmd1 = " grep -irE '^[^#]*proxy_ssl_verify\s+on;' /etc/nginx"
    cmd = subprocess.check_output(cert_cmd, shell=True).decode().strip()  
    cmd1 = subprocess.check_output(cert_cmd1, shell=True).decode().strip()  
    if cmd and cmd1:
        print("[+] The upstream traffic server certificate is trusted ")
        os.system(cert_cmd)  
        os.system(cert_cmd1)  

    elif not (cmd and cmd1):
        print("[-] The upstream traffic server certificate is not trusted and implemented")
        os.system(cert_cmd) 
        os.system(cert_cmd1) 
        example = ''' 
proxy_ssl_trusted_certificate /etc/nginx/trusted_ca_cert.crt;
proxy_ssl_verify on;

        '''
        print("Remediation : \nObtain the full certificate chain of the upstream server in .pem format. Then reference that file in the location block as part of the proxy_ssl_trusted_certificate directive. Implement the proxy_ssl_trusted_certificate and proxy_ssl_verify directives as shown below as part of the location block you are using to send traffic to your upstream server.:\n" + example )      
 except subprocess.CalledProcessError :
        print("[-] The proxy_ssl_trusted_certificate or proxy_ssl_verify directive does not exist or both does not exist ")
        os.system(cert_cmd) 
        os.system(cert_cmd1) 
def session_tickets():
 print("[+] Ensure session resumption is disabled to enable perfect forward security ")
 try:
    ssl_cmd = "grep -ir ssl_session_tickets /etc/nginx "
    cmd = subprocess.check_output(ssl_cmd, shell=True).decode().strip()
    ssl = re.findall(r"(off|OFF)", cmd, re.IGNORECASE)

    if not ssl:
        print("[-] Session resumption is disabled ")
        os.system(ssl_cmd)  
        example = ''' 
ssl_session_tickets off;

        '''
        print("Remediation : \nEnsure your NGINX server has access to your CA's OCSP server and enable it on nginx by doing the following:\n" + example )     
    else:
        print("[+] Session resumption is enabled")
        os.system(ssl_cmd)    
 except subprocess.CalledProcessError :
        print("[-] Session resumption does not exist")
        os.system(ssl_cmd)  
        example = ''' 
ssl_session_tickets off;
        '''
        print("Remediation : \n Turn off the ssl_session_tickets directive as part of any server block in your nginx configuration:\n" + example )     
def http2():
 print("[+] Ensure HTTP/2.0 is used ")
 try:
    http2_cmd = "grep -ir '^[^#]*http2' /etc/nginx "
    cmd = subprocess.check_output(http2_cmd, shell=True).decode().strip()


    if cmd:
        print("[-] HTTP/2.0 is used ")
        os.system(http2_cmd)  
        example = ''' 
server {
 listen 443 ssl http2;
}

        '''
    else:
        print("[+]  HTTP/2.0 is not used")
        os.system(http2_cmd)  
        print("Remediation : Open the nginx server configuration file (or vhosts file based on your configurations) and configure all listening ports with http2, similar to that of this :\n" + example)

 except subprocess.CalledProcessError :
        print("[-] HTTP/2.0 directive does not exists")
        os.system(http2_cmd)  
        example = ''' 
server {
 listen 443 ssl http2;
}
        '''
        print("Remediation : Open the nginx server configuration file (or vhosts file based on your configurations) and configure all listening ports with http2, similar to that of this example:\n" + example)

def ciphers():
 print("[+] Ensure only Perfect Forward Secrecy Ciphers are Leveraged ")
    # Search for ssl_ciphers and proxy_ssl_ciphers in /etc/nginx directory
 result = subprocess.run(["grep", "-ir", "ssl_ciphers\|proxy_ssl_ciphers", "/etc/nginx/"], stdout=subprocess.PIPE)
 output = result.stdout.decode()

    # Check if either ssl_ciphers or proxy_ssl_ciphers contain the cipher string
 regex = re.compile(r'.* EECDH:EDH:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA;.*')
 if regex.search(output):
        # Check if the cipher string is commented or not
    regex_commented = re.compile(r'^\s*#\s*(ssl_ciphers|proxy_ssl_ciphers)\s.*$|^(\s*ssl_ciphers|proxy_ssl_ciphers)\s.*')
    if regex_commented.search(output):
            print("[-] Cipher string found in nginx config file, but it is commented.")
            example = ''' 

ssl_ciphers EECDH:EDH:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA;
        '''
            example1 = ''' 

proxy_ssl_ciphers EECDH:EDH:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA;

        '''
            print(f"[+] Remediation:\n Ensure that only ciphers that are compatible with perfect forward secrecy are used. ECDHE/EECDH ciphers and DHE/EDH ciphers support this capability by doing the following:\n " + example +"\n" +example1)
    else:
            print("[+] Cipher string found in nginx config file.")
 else:
        print("[-] Cipher string not found in nginx config file.")
def approved_HTTP():
 print("[+] Check for unapproved HTTP methods ")
 open_methods = []
 for method in ['OPTIONS', 'TRACE', 'CONNECT','DELETE']:
    response = requests.request(method, url,allow_redirects=False)
    if response.status_code != 444  :
        open_methods.append(method)
 if open_methods:
    example1 = ''' 

if ($request_method !~ ^(GET|HEAD|POST)$) {
 return 444;
}


        '''
    
    print(f"{Fore.RED}[-] Open HTTP methods detected: ", ", ".join(open_methods))
    print(f"[+] Remediation:\n Add the following into a server or location block in your nginx.conf\n " +example1)   
 else:
    print(f"{Fore.RED}[-] No HTTP methods detected: ", ", ".join(open_methods))  
def ciphers():
 print("[+] Ensure only Perfect Forward Secrecy Ciphers are Leveraged ")
    # Search for ssl_ciphers and proxy_ssl_ciphers in /etc/nginx directory
 result = subprocess.run(["grep", "-ir", "ssl_ciphers\|proxy_ssl_ciphers", "/etc/nginx/"], stdout=subprocess.PIPE)
 output = result.stdout.decode()

    # Check if either ssl_ciphers or proxy_ssl_ciphers contain the cipher string
 regex = re.compile(r'.* EECDH:EDH:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA;.*')
 if regex.search(output):
        # Check if the cipher string is commented or not
    regex_commented = re.compile(r'^\s*#\s*(ssl_ciphers|proxy_ssl_ciphers)\s.*$|^(\s*ssl_ciphers|proxy_ssl_ciphers)\s.*')
    if regex_commented.search(output):
            print("[-] Cipher string found in nginx config file, but it is commented.")
            example = ''' 

ssl_ciphers EECDH:EDH:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA;
        '''
            example1 = ''' 

proxy_ssl_ciphers EECDH:EDH:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA;

        '''
            print(f"[+] Remediation:\n Ensure that only ciphers that are compatible with perfect forward secrecy are used. ECDHE/EECDH ciphers and DHE/EDH ciphers support this capability by doing the following:\n " + example +"\n" +example1)
    else:
            print("[+] Cipher string found in nginx config file.")
 else:
        print(f"{Fore.RED}[-] Cipher string not found in nginx config file.")
             
def timeout_values():
 print("[+] Check for request limits controls ")    
 try:
   output = subprocess.check_output(['grep', '-ir', '-E' , 'client_body_timeout|client_header_timeout', '/etc/nginx']).decode('utf-8')
 
   if " client_body_timeout 10;" in output and " client_header_timeout 10;" in output:
     if "#" not in output:

        print(f"[+]  Both client_body_timeout and client_header_timeout are configured and uncommented.")
  
     else:
        
        print(f"[-] Both client_body_timeout and client_header_timeout are configured but at least one is commented. .")
        example = ''' 

client_body_timeout 10;
client_header_timeout 10;

        '''
        print("Remediation : \nFind the HTTP or server block of your nginx configuration and add the client_header_timeout and client_body_timeout  directive set to the configuration. :\n" + example )            
 except subprocess.CalledProcessError :
    print("[-]  Either client_body_timeout or client_header_timeout is not configured.")
    example = ''' 
client_body_timeout 10;
client_header_timeout 10;

        '''
    print("Remediation : \nFind the HTTP or server block of your nginx configuration and add the client_header_timeout and client_body_timeout  directive set to the configuration. : :\n" + example )                      
 try:
   output1 = subprocess.check_output(['grep', '-ir', 'client_max_body_size', '/etc/nginx']).decode('utf-8')
 
   if " client_max_body_size 100K;" in output1 :
     if "#" not in output1:

        print(f"[+] Client_max_body_size is configured and uncommented.")
  
     else:
        
        print(f"{Fore.RED}[-] client_max_body_size is configured but at least one is commented.")
        example = ''' 

client_max_body_size 100K;
        '''
        print("Remediation : \nFind the HTTP or server block of your nginx configuration and add the client_max_body_size  directive set to the configuration. :\n" + example )            
 except subprocess.CalledProcessError :
    print("[-] client_max_body size is not configured.")
    example = ''' 
client_max_body_size 100K;

        '''
    print("Remediation : \nFind the HTTP or server block of your nginx configuration and add the client_max_body_size directive set to the configuration. :\n" + example )                
 try:
  output2 = subprocess.check_output(['grep', '-ir', 'large_client_header_buffers', '/etc/nginx']).decode('utf-8')

  if "large_client_header_buffers 2 1k;" in output2 :
    if "#" not in output2:

        print(f"[+]large_client_header_buffers  is configured and uncommented.")
        example = ''' 
large_client_header_buffers 2 1k;

        '''
        print("Remediation : \nFind the HTTP or server block of your nginx configuration and add the large_client_header_buffers  directive set to the configuration. :\n" + example )            
    else:
        
        print("[-] large_client_header_buffers is configured but at least one is commented.")
 except subprocess.CalledProcessError :
    print(f"{Fore.RED}[-] large_client_header_buffers  is not configured.")
    example = ''' 
large_client_header_buffers 2 1k;

        '''
    print("Remediation : \nFind the HTTP or server block of your nginx configuration and add the large_client_header_buffers  directive set to the configuration. :\n" + example )                
def ip_ratelimit():
 print("[+] Search for limit_conn_zone and limit_conn directives and check whether exist to limit simultaneous connections from one IP Address and the number of requests an IP address may make to a server in a given period of time")
 config_files = ['/etc/nginx/nginx.conf', '/etc/nginx/']

# Search for limit_conn_zone and limit_conn directives
 found_limit_conn_zone = False
 found_limit_conn = False
 found_limit_req_zone = False
 found_limit_req = False
 try:
  for file in config_files:
    output = subprocess.check_output(['grep', '-Er', '-e', '^\s*limit_conn_zone\s|^\s*limit_conn\s', '-e', '^\s*limit_req_zone\s|^\s*limit_req\s', file]).decode('utf-8')
    if output:
        for line in output.splitlines():
            if not line.startswith('#'):
                if 'limit_conn_zone' in line:
                    found_limit_conn_zone = True
                elif 'limit_conn' in line:
                    found_limit_conn = True
                elif 'limit_req_zone' in line:
                    found_limit_req_zone = True
                elif 'limit_req' in line:
                    found_limit_req = True

  if found_limit_conn_zone and found_limit_conn and found_limit_req_zone and found_limit_req:
    print(f"{Fore.WHITE}[+] All directives found and properly configured.")
 except subprocess.CalledProcessError :
    print(f"{Fore.RED}[-] One or more directives not found or improperly configured.")   
    example = ''' 
http {
 limit_conn_zone $binary_remote_addr zone=limitperip:10m; 
 server {
 limit_conn limitperip 10;
 }
}

        '''
    example1= ''' 
http {
 limit_conn_zone $binary_remote_addr zone=limitperip:10m; 
 server {
 limit_conn limitperip 10;
 }
}

        '''
    print("Remediation : \nFind the HTTP or server block of your nginx configuration and change the configurations to the following :\n" + example + "\n" +example1)                
def http_headers():
 print("[+] Check HTTP headers to see whether they are configured correctly")
# Check for X-Frame-Options header

# Check if there is any output
 try:
  cmd= "grep -ir X-Frame-Options /etc/nginx"
  output = subprocess.check_output(cmd, shell=True).decode().strip()
  if output:
    # Check if the line is not commented out
    if not output.startswith('#'):
        if "'SAMEORIGIN'" in output or '"SAMEORIGN"' in output:
            print(f"[+] X-Frame-Options header is configured and enabled.")
        else:
            print(f"{Fore.RED}[-] X-Frame-Options is not configured properly.")

        example1= ''' 
add_header X-Frame-Options "SAMEORIGIN" always;


        '''
        print("Remediation : \nFind the HTTP or server block of your nginx configuration and change the configurations to the following :\n" + example1)                
   
    else:
    
        print(f"{Fore.RED}[-] X-Frame-Options header is commented out and not enabled.")
 except subprocess.CalledProcessError :
        print(f"{Fore.RED}[-] X-Frame-Options header is not configured and not enabled.")
        example1= ''' 
add_header X-Frame-Options "SAMEORIGIN" always;


        '''
        print("Remediation : \nFind the HTTP or server block of your nginx configuration and change the configurations to the following :\n" + example1)                
# Check for X-Content-Type-Options header

# Check if there is any output
 try:
  cmd1= "grep -ir   X-Content-Type-Options /etc/nginx"
  output1 = subprocess.check_output(cmd1, shell=True).decode().strip()
  if output1:
    # Check if the line is not commented out
    if not output1.startswith('#'):
        if "'nosniff'" in output or '"nosniff"' in output1:
            print(f"[+] X-Content-Type-Options header is configured and enabled.")
        else:
            print(f"{Fore.RED}[-] X-Content-Type-Options header is not configured properly.")
            example1= ''' 
add_header X-Content-Type-Options "nosniff" always;


        '''
        print("Remediation : \nFind the HTTP or server block of your nginx configuration and change the configurations to the following :\n" + example1)                
        
 except subprocess.CalledProcessError :
    print(" X-Content-Type-Options header  is not configured and not enabled.")

 try:
   cmd1= "grep -ir Content-Security-Policy /etc/nginx"
   output2 = subprocess.check_output(cmd1, shell=True).decode().strip()
# Check if there is any output
   if output2:
    # Check if the line is not commented out and is properly configured
    if not output2.startswith('#'):
        if "default-src 'self'" in output2:
            print(f"[+] Content Security Policy (CSP) is enabled and configured properly.")
        else:
            print(f"{Fore.RED}[-] Content Security Policy (CSP) is not configured properly.")
            example1= ''' 
add_header X-Content-Type-Options "nosniff" always;


        '''
        print("Remediation : \nFind the HTTP or server block of your nginx configuration and change the configurations to the following :\n" + example1)                
 except subprocess.CalledProcessError :
    print(f"{Fore.RED}[-] Content Security Policy (CSP) is not configured and not enabled.")
    example1= ''' 
add_header X-Content-Type-Options "nosniff" always;


        '''
    print("Remediation : \nFind the HTTP or server block of your nginx configuration and change the configurations to the following :\n" + example1)                

# Check if there is any output
 try:
  cmd3= "grep -r  Referrer-Policy /etc/nginx"
  output3 = subprocess.check_output(cmd3, shell=True).decode().strip()
  if output3:
    # Check if the line is not commented out
    if not output3.startswith('#'):
        if "'no-referrer'" in output3 or '"no-referrer"':
           print(f"[+] Referrer Policy is enabled and configured properly.")
        else:
           print(f"{Fore.RED}[-] Referrer Policy is commented out and not enabled.")
           example1= ''' 
add_header X-Content-Type-Options "nosniff" always;


        '''
    print("Remediation : \nFind the HTTP or server block of your nginx configuration and change the configurations to the following :\n" + example1)                           
 except subprocess.CalledProcessError : 
    print(f"{Fore.RED}[-] Referrer Policy is not configured and not enabled.")
    example1= ''' 
add_header X-Content-Type-Options "nosniff" always;


        '''
    print("Remediation : \nFind the HTTP or server block of your nginx configuration and change the configurations to the following :\n" + example1)                
def check_open_ports(url):
    print("[+] Check whether vulnerable ports are open")
    open_ports = []
    for port in [21, 22, 23, 25,53, 137,445]:
        try:
            r = requests.get(url + f"{port}",allow_redirects=False)
            if r.status_code == 200:
                open_ports.append(port)
        except requests.exceptions.ConnectionError:
            pass
    if len(open_ports) > 0:
        print(f"{Fore.RED}[-] Warning: Open ports detected: {open_ports}")
    else:
        print("[+] No open ports detected")
def check_session_fixation(url):
    print("[+] Check for secure and HttpOnly flags")
    # Generate a random cookie value and set it in the session
    session = requests.Session()
    cookie_name = str(uuid.uuid4())
    cookie_value = str(uuid.uuid4())
    session.cookies.set(cookie_name, cookie_value)

    # Make a request to the target URL
    response = session.get(url, allow_redirects=False)

    # Check for secure and HttpOnly flags in session cookie
    session_cookie = session.cookies.get_dict()[cookie_name]
    secure_flag = 'secure' in session_cookie
    http_only_flag = 'HttpOnly' in session_cookie
    if secure_flag and http_only_flag:
        print('[+] Session cookie has secure and HttpOnly flags')
    else:
        print(f'{Fore.RED}[-] Session cookie does not have secure and/or HttpOnly flags')


    # Attack using server-generated SID
    server_sid = response.cookies.get(cookie_name)
    url = url + f'?SID={server_sid}'
    attack_response = requests.get(url, cookies=session.cookies.get_dict())
    if attack_response.status_code == 200:
        print(f'{Fore.RED}[-] Session fixation vulnerability detected - server-generated SID was accepted')
        print(attack_response.status_code)
    else:
        print('[+] Server only accepts newly generated SIDs - not vulnerable to session fixation attack')
def check_cors_vuln(url):
    print("[+] Check for CORS vulnerabiltites" )
    # Send a request with an origin header to test CORS configuration
    headers = {'Origin': 'https://malicious-site.com'}
    response = requests.get(url, headers=headers,allow_redirects=False)

    # Check for Access-Control-Allow-Origin header
    if 'access-control-allow-origin' not in response.headers:
        print('[+] Missing Access-Control-Allow-Origin header!')
    else:
        allowed_origin = response.headers['access-control-allow-origin']
        if allowed_origin == '*':
            print('[+] CORS misconfiguration: Allow-Origin set to wildcard (*)')
        elif 'https://malicious-site.com' not in allowed_origin:
            print(f'{Fore.RED}[-] CORS misconfiguration: Allow-Origin does not include malicious site')
        else:
            print(f'{Fore.RED}[-] CORS is configured correctly.')

if __name__ == '__main__':
  banner = '''
                _                  _                 __       _                  
                 (_)                / |_              [  |  _  / |_                
 _ .--.   .--./) __  _ .--.  _   __`| |-'_ .--.  ,--.  | | / ]`| |-' .--.  _ .--.  
[ `.-. | / /'`\;[  |[ `.-. |[ \ [  ]| | [ `/'`\]`'_\ : | '' <  | | / .'`\ [ `/'`\] 
 | | | | \ \._// | | | | | | > '  < | |, | |    // | |,| |`\ \ | |,| \__. || |     
[___||__].',__` [___|___||__|__]`\_]\__/[___]   \'-;__[__|  \_]\__/ '.__.'[___]    
        ( ( __))   
        
            A common vulnerability scanner for misconfigurations in NGINX Web Server
'''

  if len(sys.argv) != 2:
    print(f"{Fore.WHITE}Usage: python3 nginxtraktor.py https://example.com ")
    sys.exit()
  if sys.argv[1].endswith("/"):
     print(f"{Fore.WHITE}[?] Please provide the URL without slash at the end")
     sys.exit()

  url = sys.argv[1]
  basereq = requests.get(url, verify=False,allow_redirects=False)
  print(Fore.BLUE+banner)
  print(f"{Fore.WHITE} Section 1 : Initial Setup")
  check_nginx_installed()
  installed_from_source()
  print(f"{Fore.WHITE} Section 2 : Basic Configurations")
  audit_http_dav_module()
  audit_gzip_modules()
  check_url_directory_listing(url)
  print(f"{Fore.WHITE} Section 2 : Basic Configurations")
  account_security()
  directories_perms()
  restricted_perms()
  secure_pid()
  core_dump()
  network_conn()
  curl_host(url)
  keepalive_timeout()
  send_timeout()
  server_tokens (url)
  error_html()
  hidden_file()
  reverse_proxy()
  print(f"{Fore.WHITE} Section 3 : Logging")
  access_log_enabled()
  error_log()
  log_files()
  error_log_syslog()
  access_log_syslog()
  proxies()
  print(f"{Fore.WHITE} Section 4 : Encryption")
  check_redirect()
  trust_chain_key()
  private_key_perm()
  TLS()
  weak_ciphers()
  ssl_dhparam()
  crlf_injections(url)
  OCSP()
  HSTS()
  proxy_ssl()
  trusted_cert()
  session_tickets()
  http2()
  ciphers()
  print(f"{Fore.WHITE} Section 5 :  Request Filtering and Restrictions")
  approved_HTTP()
  timeout_values()
  ip_ratelimit()
  http_headers()
  print(f"{Fore.WHITE} Additional Checks for NGINX Web Server")
  check_open_ports(url)
  check_session_fixation(url)
  block_ips()
  crlf_injections(url)
  check_cors_vuln(url)
