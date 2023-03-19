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

banner = '''
████████╗ ██████╗ ███╗   ███╗ ██████╗ █████╗ ████████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
╚══██╔══╝██╔═══██╗████╗ ████║██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
   ██║   ██║   ██║██╔████╔██║██║     ███████║   ██║   ███████║██║   ██║██║  ██║██║   ██║   
   ██║   ██║   ██║██║╚██╔╝██║██║     ██╔══██║   ██║   ██╔══██║██║   ██║██║  ██║██║   ██║   
   ██║   ╚██████╔╝██║ ╚═╝ ██║╚██████╗██║  ██║   ██║   ██║  ██║╚██████╔╝██████╔╝██║   ██║   
   ╚═╝    ╚═════╝ ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝                                                                               
'''

def run_all_sections():
    section1()
    section2()
    section3()
    section4()
    section5()
    section6()
    section7()
    section8()
    section9()
   section10()

def run_selected_function():
    section_list = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
    choice = input("Enter section number to audit eg, (1 2 3): ")
    choices = choice.split()
    for choice in choices:
        try:
            choice = int(choice)
            if choice in section_list:
                if choice == 1:
                    section1()
                elif choice == 2:
                    section2()
                elif choice == 3:
                    section3()
                elif choice == 4:
                    section4()
                elif choice == 5:
                    section5()
                elif choice == 6:
                    section6()
                elif choice == 7:
                    section7()
                elif choice == 8:
                    section8()
                elif choice == 9:
                    section9()
                elif choice == 10:
                    print('section10')
                     section10()
            else:
                print(f"Invalid choice {choice}. Please try again.")
        except ValueError:
            print(f"Invalid choice {choice}. Please enter a valid integer.")
print(banner)
print("Select an option:")
print("1. Run all sections")
print("2. Run a specific section")

choice = input("Enter option number: ")

if choice == "1":
    run_all_sections()
elif choice == "2":
    run_selected_function()
else:
    print("Invalid choice. Please try again.")

