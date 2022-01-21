import whois
import json
import validators
import dns.resolver
from ipwhois.net import Net
from ipwhois.asn import IPASN
import signal
from sys import platform

if platform.startswith('linux'):
        import readline


whoisReturn = ["domain_name", "registrar", "creation_date","expiration_date", "name_servers", "status", "dnssec"]
dnsRec = ['A', 'MX', 'TXT', 'NS', 'SOA']
ipData = {'asn_country_code': 'Country', 'asn_description': 'Owner'}
subData = ['www.', 'mail.', 'ftp.']
running = 1

# define colors
class bcolors:
    OKBLUE = '\033[1;34m'
    OKCYAN = '\033[1;36m'
    OKGREEN = '\033[0;32m'
    WARNING = '\033[1;31m'
    CLEAR = '\033[0;0m'

# Gets the whois data and reduces it down to only the values we care about
def domainWhois(inData):
        outData = {}
        #query whois
        w = json.dumps(whois.whois(inData), default=str)
        whoIsData = json.loads(w)
        #iterate through whoisReturn
        #for each item in whoisReturn grab the corresponding values
        for x in whoisReturn:
                if x in whoIsData:
        #append the key-value pairs to outData
                        outData[x] = whoIsData[x]
                else:
                        pass
        return json.dumps(outData)

# Looks up records that resolve to domains (MX and CNAMES usually)
def cnameLookup(inData):
        try:
                result = dns.resolver.resolve(inData, 'A')
                for rdata in result:
                        return rdata
        except:
                pass        

# Looks up the DNS records of the domain
def dnsLookup(inData):
        outData = {}
        #for record in dnsRec
        for rec in dnsRec:
        #resolve DNS against inData
                try:
                        result = dns.resolver.resolve(inData, rec)
                        for rdata in result:
                                tmpData = str(rdata).strip(" .0123456789")
                                if validators.domain(tmpData):
                                        cname = cnameLookup(tmpData)
                                        rdata = f"{rdata} {bcolors.OKCYAN}>{bcolors.CLEAR} {cname}"
                                if rec in outData:
                                        outData[rec].append(rdata)
                                else:
                                        outData[rec] = [rdata]
                except Exception as e:
                        outData[rec] = [e]
        return json.dumps(outData, default=str)

# Takes the whois json data from domainWhois() and prints it out in a nicer format to view in terminal
def displayData(inDataWhois, inDataDNS, inDataSub):
        #display whois
        data = json.loads(inDataWhois)
        print(bcolors.OKGREEN, "--WHOIS--", bcolors.CLEAR)
        try:
                for i in data:
                        if isinstance(data[i], str):
                                print(bcolors.OKCYAN, i, bcolors.CLEAR, ":", data[i])
                        else:
                                for j in data[i]:
                                        print(bcolors.OKCYAN, i, bcolors.CLEAR, ":", j)
                print("\n")
        except Exception as e:
                print(bcolors.WARNING + "ERROR. TLD is shit")

        #display dns
        print(bcolors.OKGREEN, "--DNS--", bcolors.CLEAR)
        dataDns = json.loads(inDataDNS)
        for i in dataDns:
                for j in dataDns[i]:
                        print(bcolors.OKCYAN,"~",bcolors.CLEAR, i,bcolors.OKBLUE, j, bcolors.CLEAR)
        
        #display subdomains
        print(bcolors.OKGREEN, "--SUBDOMAINS--", bcolors.CLEAR)
        dataSub = json.loads(inDataSub)
        for i in dataSub:
                print(dataSub[i])
        print('\n')

#self explanatory lol
def checkIP(inData):
        ipnet = Net(inData)
        ipobj = IPASN(ipnet)
        results = ipobj.lookup()
        for i in ipData:
                print(f"{ipData} ~ {results[i]}")

#lookup some default subdomains 
def subLookup(inData):
        outData = {}
        for i in subData:
                dom = f"{i}{inData}"
                outData[i] = f"{bcolors.OKBLUE} {i} {bcolors.OKCYAN} > {bcolors.CLEAR} {cnameLookup(dom)}"
        return json.dumps(outData, default=str)

def userInput(inData):
        inData.strip(" ")
        if validators.ipv4(inData):
                checkIP(inData)
        elif validators.domain(inData):
                displayData(domainWhois(inData),dnsLookup(inData),subLookup(inData))   
        else:
                print(bcolors.WARNING + "Enter a real domain" + bcolors.CLEAR)

# TODO
# convert to flask so can be used as server/client
# add IP reverse lookup

def signal_handler(singal, frame):
    quit()

signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
        while running == 1:
                userInput(input("Enter domain: "))
        
