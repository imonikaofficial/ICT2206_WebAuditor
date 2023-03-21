# ICT2206_WebAuditor
# WebAuditor

WebAuditor is a suite of Audit tools to analyze the configurations of Apache Tomcat and NGINX web servers in Ubuntu 20.04 systems

## Prerequisites
1. Ubuntu 20.04 system (tools tested on this)
2. beautifulsoup4
3. colorama

## Install:

```
sudo -i (gain root access to your machine)
git clone https://github.com/imonikaofficial/ICT2206_WebAuditor.git
cd ICT2206_WebAuditor
pip3 install -r requirements.txt
```

## Configurations to run the audit tool for Tomcat
```
# Setting Permanent Environment Variables for Tomcat on Ubuntu
## Overview
This guide provides step-by-step instructions on how to set permanent environment variables for Tomcat on Ubuntu. Specifically, you will need to set the CATALINA_HOME and CATALINA_BASE variables to point to the installation directory of Tomcat.

## Prerequisites
1. Ubuntu operating system
2. Nano text editor

## Steps
Open the /etc/environment file using the Nano text editor:
- sudo nano /etc/environment

Add the following lines to the end of the file:
- CATALINA_HOME="/opt/tomcat/"
- CATALINA_BASE="/opt/tomcat/"
Note: /opt/tomcat is the default installation directory of Tomcat

Save the changes by pressing Ctrl+O, and then exit Nano by pressing Ctrl+X.

Apply the changes by running the following command:

reload

## Verifying the Setup
To verify that the environment variables have been set correctly, you can run the following commands:
- echo $CATALINA_HOME
- echo $CATALINA_BASE
```
## Configurations to run the audit tool for NGINX web server
```
## Steps to run the tool
sudo -i
python3 nginxtraktor.py https://example.com (your_web_server_url)

YouTube Demo Link:https://www.youtube.com/watch?v=lxaVUWANBI4
