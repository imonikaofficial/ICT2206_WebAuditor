# ICT2206_WebAuditor

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
