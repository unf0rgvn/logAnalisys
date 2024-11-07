import fnmatch
import re
from datetime import datetime
from babel.dates import format_datetime

nList = []  # Raw log in list format.
#suspect = '' # All suspected ip addresses.
tool = [] # Tools that were used.
starEnd = []

# How many times the tools appeared.
# This is a test.
# New line

def getData(file):
    sus = []
    suspect = ''

    with open(file, 'r') as file:
        read = file.read()

    for l in read.split("\n"):
        nList.append(l.split('"'))


    # Searchs for everything that contains Nmap, Nikto and qlmap
    # and add to tool list.
    for n in nList:
        a = fnmatch.filter(n, "*Nmap*") or fnmatch.filter(n, "*Nikto*") or fnmatch.filter(n, "*qlmap*")
        if a:
            transform = str(n[0]).split(" ")
            tool.append(a)
            sus.append(transform[0])
            starEnd.append(transform[3])

    if sus.count(sus[0]) == len(sus):
        suspect = str(set(sus))
    
    return suspect.replace("'", "").replace("{", "").replace("}", "")


def usedTools():
    nmap_C = 0 
    nikto_C = 0
    other = 0
    for a in tool:
        try:
            c = str(a)
            try:
                b = re.search("Nmap", c) or re.search("Nikto", c)
                if b[0] == "Nmap":
                    nmap_C+=1
                elif b[0] == 'Nikto':
                    nikto_C+=1
                else:
                    other+=1
            except re.error as err:
                print(f"The program failed with the erro {err}")
                print(err)
                break
        except IndexError as rre:
            continue

    return nmap_C, nikto_C, other

def getTime():
    start = format_datetime(datetime.strptime(starEnd[0].replace('[',''), '%d/%b/%Y:%H:%M:%S'), "d/MM/YYYY:HH:mm:s")
    end = format_datetime(datetime.strptime(starEnd[-1].replace('[',''), '%d/%b/%Y:%H:%M:%S'), "d/MM/YYYY:HH:mm:s")
    return start, end


def main():
    file = input("Please, insert the name of your file: ")
    suspect = getData(file)
    nmap_C,nikto_C, other = usedTools()
    start, end = getTime()

    print(f"Suspect IP Address: {suspect}")
    print(f"The Nmap tool was used {nmap_C} times, and Nikto {nikto_C} times.")
    print(f"The attack started in {start} and ended in {end}.")


if __name__ == '__main__':
    main()

