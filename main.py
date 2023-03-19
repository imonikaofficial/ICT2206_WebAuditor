from Section1 import *
from Section2 import *
from Section3 import *
from Section4 import *
from Section5 import *
from Section6 import *
from Section7 import *
from Section8 import *
from Section9 import *
from Section10 import *

csvFile = "C:\Users\Gaindy\Desktop\2206\output.csv"
banner = '''
████████╗ ██████╗ ███╗   ███╗ ██████╗ █████╗ ████████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
╚══██╔══╝██╔═══██╗████╗ ████║██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
   ██║   ██║   ██║██╔████╔██║██║     ███████║   ██║   ███████║██║   ██║██║  ██║██║   ██║   
   ██║   ██║   ██║██║╚██╔╝██║██║     ██╔══██║   ██║   ██╔══██║██║   ██║██║  ██║██║   ██║   
   ██║   ╚██████╔╝██║ ╚═╝ ██║╚██████╗██║  ██║   ██║   ██║  ██║╚██████╔╝██████╔╝██║   ██║   
   ╚═╝    ╚═════╝ ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝    
         A common vulnerability scanner for misconfigurations in Apache Tomcat Web server
'''

def run_all_sections():
    section1()
    section2()
    section3()
    section4()
    section5()
    section6(csvFile)
    section7(csvFile)
    section8(csvFile)
    section9(csvFile)
    section10(csvFile)

def run_selected_function():
    choice = input("Enter section number to audit (1-10): ")
    if choice == "1":
        section1()
    elif choice == "2":
        section2()
    elif choice == "3":
        section3()
    elif choice == "4":
        section4()
    elif choice == "4":
        section4()
    elif choice == "5":
        section5()
    elif choice == "6":
        section6(csvFile)
    elif choice == "7":
        section7(csvFile)
    elif choice == "8":
        section8(csvFile)
    elif choice == "9":
        section9(csvFile)
    elif choice == "10":
        section10(csvFile)
    else:
        print("Invalid choice. Please try again.")
print(banner)
print("Select an option:")
print("1. Run all sections")
print("2. Run a specific section")

choice = input("Enter option number: ")

if choice == "1":
    run_all_sections()
elif choice == "2":
    run_selected_section()
else:
    print("Invalid choice. Please try again.")

