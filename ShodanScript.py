from email import header
from tkinter import font
from shodan import Shodan
from tabulate import tabulate
from shodan.cli.helpers import get_api_key
from fpdf import FPDF
import csv

def sortList(e):
    return e["cvss"]

api = Shodan(get_api_key())
pdf = FPDF()

fields = ['IP', 'CVE', 'CVSS', "CVE'ER", 'High CVES', 'Critical CVES']
table =  [['IP', 'CVSS', "CVE'ER", 'High CVES', 'Critical CVES']]

print('Welcome to VULN scanner')

x = input('Do you want to search for a organisation or specific IPs? Enter 1 for organisation. Enter 2 for specific IP.\n')

userInput = ""
results = []
inputs = []
ports = []
str2 = ""

def f(x):
    global results
    global userInput
    str1 = ""
    match x:
        case '1':
            userInput = input('Enter organisation to scan for vulns: ')
            limits = input('How many results do you wish to find? One credit can find up to 100 results: ')
            results = api.search(f'org:{userInput} has_vuln:true', limit=limits)
        case '2':
            while(True):
                userInput = input('Enter the specific IP you wish to look up: ')
                inputs.append(userInput)
                continueInput = input('Do you wish to start the search? Type yes to start search. Press enter to look up more IPs.\n')
                if(continueInput.lower() == "yes"):
                    for ele in inputs: 
                        str1 += ele
                    results = api.search(f'ip:{str1} has_vuln:true')
                    break
                else:
                    inputs.append(',')

f(x)

with open('Output for ' + userInput + '.csv', 'w', encoding='UTF8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(fields)

    for result in results['matches']:
        pdf.add_page()

        numberOfCVEs = 0
        numberOfCriticalCVE = 0
        numberOfHighCVE = 0
        nameCVE = []
        pdf.set_font("Arial", 'B', size = 20)
        pdf.cell(200, 10, txt = "IP: {}".format(result['ip_str']),
        ln = 1,  align = 'C')
        pdf.set_font("Arial", 'B', size = 16)
        #for item in result:
        #    for ele in item: 
        #        str2 += ele
        #    ports.append(str2)  -- Attempt at getting ports printed out
        #pdf.cell(200, 10, txt="Ports: {}".format(ports),
        #align='C')
        pdf.cell(200, 10, txt = "{}".format(result['org']),
        ln = 1,  align = 'C')
        pdf.set_font("Arial", size = 14)
        dictIo = []
        key = 'vulns'
        if(key in result):
            for item in result['vulns']:
                dictIo.append({"CVE":item,"cvss": float(result['vulns'][item]['cvss']),"desc":result['vulns'][item]['summary']})
                numberOfCVEs = numberOfCVEs + 1
                cvssScore = float(result['vulns'][item]['cvss'])
                nameCVE.append(item)

                if cvssScore >= 9:
                    numberOfCriticalCVE = numberOfCriticalCVE + 1
                elif 9 > cvssScore >= 7: 
                    numberOfHighCVE = numberOfHighCVE + 1

            dictIo.sort(key=sortList, reverse=True)
            pdf.cell(200, 14, txt = "Total amount of CVE found: {}".format(numberOfCVEs),
            ln = 1, align = 'L')
            dictCounter = 0
            for item in dictIo:
                pdf.set_font("Arial", size = 14)
                pdf.cell(200, 14, txt = "{}".format(dictIo[dictCounter]['CVE']) + "   CVSS: {}".format(dictIo[dictCounter]['cvss']),
                ln = 1, align = 'L')
                pdf.set_font("Arial", size = 12)
                pdf.multi_cell(180, 5, txt = "Description:\n{}".format(dictIo[dictCounter]['desc']), 
                align = 'L')
                pdf.multi_cell(200, 10, txt = "",
                align= 'L')
                dictCounter= dictCounter+1


            rows = [result['ip_str'], nameCVE, cvssScore,
                    numberOfCVEs, numberOfHighCVE, numberOfCriticalCVE]
            tableData = [result['ip_str'], cvssScore,
                    numberOfCVEs, numberOfHighCVE, numberOfCriticalCVE]

            table.append(tableData)

            writer.writerow(rows)
print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))
pdf.output('Rapport for ' + userInput + '.pdf')
