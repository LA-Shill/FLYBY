# !/usr/bin/env python
# Name:     flyby.py
# By:       Liam Shillinglaw
# Date:     26.02.2020
# Version   0.3
# -----------------------------------------------

# Library imports
from censys.ipv4 import CensysIPv4
import csv
from datetime import date, datetime
import re
import pymongo
import json
import os
import sys
import json
import requests
from fuzzywuzzy import fuzz
from fuzzywuzzy import process

# Hard coded variables
UID = " "
SECRET = " "
API_URL = "https://censys.io/api/v1"

#DB Stuff
client = pymongo.MongoClient('localhost', 27017)
db = client['flyby']

def censys_grab(ipRange, apis, options):
    # ADD - Switch Case for API selection in seperate functions
    fName = ipRange + "_report_" + str(date.today()) + ".csv"
    fName = re.sub(r'[\\/*?:"<>|]', "_", fName)

    ipv4 = CensysIPv4(api_id=UID, api_secret=SECRET)

    IPV4_FIELDS = ['ip']
    IPV4_FIELDS_TXT = ['ip']
    for item in options:
        if(item != None):
            IPV4_FIELDS_TXT.append(item)
            if (item == 'ftp') :
                IPV4_FIELDS.append('21.ftp.banner.metadata.description')
            if (item == 'ssh') :
                IPV4_FIELDS.append('22.ssh.v2.banner.software')
            if (item == 'http') :
                IPV4_FIELDS.append('80.http.get.metadata.description')
            if (item == 'https') :
                IPV4_FIELDS.append('443.https.get.metadata.description')
            if (item == 'smtp') :
                IPV4_FIELDS.append('25.smtp.starttls.metadata.description')

    results = list(ipv4.search(ipRange, IPV4_FIELDS, max_records=2000))

    # Convert keys in dict
    for d in results:
        if "21.ftp.banner.metadata.description" in d:
            d['ftp'] = d.pop('21.ftp.banner.metadata.description')
        if "22.ssh.v2.banner.software" in d:
            d['ssh'] = d.pop('22.ssh.v2.banner.software')
        if "80.http.get.metadata.description" in d:
            d['http'] = d.pop('80.http.get.metadata.description')
        if "443.https.get.metadata.description" in d:
            d['https'] = d.pop('443.https.get.metadata.description')
        if "25.smtp.starttls.metadata.description" in d:
            d['smtp'] = d.pop('25.smtp.starttls.metadata.description')

    with open(fName, 'w', newline='') as f:
        writer = csv.DictWriter(f, IPV4_FIELDS_TXT)
        writer.writeheader()
        writer.writerows(results)

    dbName = re.sub(r'[/]', "_", ipRange)

    newCol = db[dbName]
    newCol.insert_many(results)

def getConfig ():
    if(os.stat("api.txt").st_size != 0) :
        fileOpen = open('api.txt', 'r').read().split(',')
    else :
        f = open("api.txt", "w")
        f.write("UID" + "," + "SECRET")
        f.close()
    return fileOpen[0], fileOpen[1]

def setConfig (u, s):
    f = open("api.txt", "w")
    f.write(u + "," + s)
    f.close()

def stats ():
    uid, secret = getConfig()
    res = requests.post(API_URL + ("/account"), auth = (uid, secret))
    if res.status_code != 200:
        return
    else:
        return res.json()

def createCpeDB () :

    db = client['cvedb']
    results = db.cpe.find({})

    f = open("cpedb.txt", "w")
    for result in results :
        f.write(result["cpe_2_2"] + '\n')
    f.close()
    print("Created file.")

def cpeDBCheck () :
    dbnames = client.list_database_names()
    if (os.path.isfile("cpedb.txt")) :
        cpe = "yup"
        return cpe

def cveDBCheck () :
    dbnames = client.list_database_names()
    if 'cvedb' in dbnames:
        cve = "yup"
        return cve

# Generate CPE for each mongodb record - Store it
def vulScan(c):
    # Quick fix for threads, needs local object - can't be passed
    db = client['flyby']
    col = db[c]
    d = col.find({})
    print(d.count())

    for result in d:
        vuls = "Secure"
        now = datetime.now()
        dTime = now.strftime("%d/%m/%Y %H:%M:%S")

        if "ftp" in result:
            print ("\nIP Address: " + result['ip'])
            print("FTP Banner: " + result['ftp'])
            vuls = cpe_gen(result['ftp'])
            if(len(vuls) > 0 and type(vuls) != str) :
                name = "ftp_cves"
                addCVE(result['ip'], vuls, c, name)
                fNameStats = name + "_scan_stats"
                curScan = {'state' : "Complete",'match': curScore, 'dTime': dTime, 'result': "vulnerable"}
            else :
                fNameStats = "scan_stats"
                curScan = {'state' : "Complete",'match': curScore, 'dTime': dTime, 'result': vuls}
            scanStats(result['ip'], c, curScan, fNameStats)
        if "ssh" in result:
            print ("\nIP Address: " + result['ip'])
            print("SSH Banner: " + result['ssh'])
            vuls = cpe_gen(result['ssh'])
            if(len(vuls) > 0 and type(vuls) != str) :
                name = "ssh_cves"
                addCVE(result['ip'], vuls, c, name)
                fNameStats = name + "_scan_stats"
                curScan = {'state' : "Complete",'match': curScore, 'dTime': dTime, 'result': "vulnerable"}
            else :
                fNameStats = "scan_stats"
                curScan = {'state' : "Complete",'match': curScore, 'dTime': dTime, 'result': vuls}
            scanStats(result['ip'], c, curScan, fNameStats)
        if "http" in result:
            print ("\nIP Address: " + result['ip'])
            print("HTTP Banner: " + result['http'])
            vuls = cpe_gen(result['http'])
            if(len(vuls) > 0 and type(vuls) != str) :
                name = "http_cves"
                addCVE(result['ip'], vuls, c, name)
                fNameStats = name + "_scan_stats"
                curScan = {'state' : "Complete",'match': curScore, 'dTime': dTime, 'result': "vulnerable"}
            else :
                fNameStats = "scan_stats"
                curScan = {'state' : "Complete",'match': curScore, 'dTime': dTime, 'result': vuls}
            scanStats(result['ip'], c, curScan, fNameStats)
        if "https" in result:
            print ("\nIP Address: " + result['ip'])
            print("HTTPS Banner: " + result['https'])
            vuls = cpe_gen(result['https'])
            if(len(vuls) > 0 and type(vuls) != str) :
                name = "https_cves"
                addCVE(result['ip'], vuls, c, name)
                fNameStats = name + "_scan_stats"
                curScan = {'state' : "Complete",'match': curScore, 'dTime': dTime, 'result': "vulnerable"}
            else :
                fNameStats = "scan_stats"
                curScan = {'state' : "Complete",'match': curScore, 'dTime': dTime, 'result': vuls}
            scanStats(result['ip'], c, curScan, fNameStats)
        if "smtp" in result:
            print ("\nIP Address: " + result['ip'])
            print("SMTP Banner: " + result['smtp'])
            vuls = cpe_gen(result['smtp'])
            if(len(vuls) > 0 and type(vuls) != str) :
                name = "smtp_cves"
                addCVE(result['ip'], vuls, c, name)
                fNameStats = name + "_scan_stats"
                curScan = {'state' : "Complete",'match': curScore, 'dTime': dTime, 'result': "vulnerable"}
            else :
                fNameStats = "scan_stats"
                curScan = {'state' : "Complete",'match': curScore, 'dTime': dTime, 'result': vuls}
            scanStats(result['ip'], c, curScan, fNameStats)

def cve_lookup(cpe) :
    # Find known vulnerabilties matching vulnerable config
    db = client['cvedb']
    cves = db.cves.find({"vulnerable_configuration" : cpe})
    cveList = []

    if (cves.count() > 0) :
        print ("Vulnerabilities found:")
        for cve in cves :
            print("CVE: " + str(cve["id"]))
            cvesDetected = {'cves' : cve["id"], 'cvss2': cve["cvss"], 'aVector' : cve["cvss-vector"]}
            cveList.append(cvesDetected)
            if (cve["cvss-vector"][:4] == "AV:N") :
                print("CVSS2: " + str(cve["cvss"]) + "                             Remotely exploitable.")
            elif (cve["cvss-vector"][:4] == "AV:L"):
                print("CVSS2: " + str(cve["cvss"]) + "                             Locally exploitable.")
            elif (cve["cvss-vector"][:4] == "AV:A"):
                print("CVSS2: " + str(cve["cvss"]) + "                             Exploitable via Adjcacent Network.")
            elif (cve["cvss-vector"][:4] == "AV:P"):
                print("CVSS2: " + str(cve["cvss"]) + "                             Physically exploitable.")
            else :
                print("CVSS2: " + str(cve["cvss"]))
    else :
        print ("No vulnerabilities found.")
        print("---------------------------------------------------------------------")
        return ("Secure")
    print("---------------------------------------------------------------------")
    return (cveList)


def cpe_gen (sValue) :
    # THIS NEEDS IMPORVED - ALSO CHECK CPE LIST? NOT EVERYTHING IS ON IT (Issue with Database!)
    # Version
    perAttribute = "cpe:2.3"
    # Applicaion = a, OS = o, Hardware = h
    part = "a"
    p1 = ""
    cpeArray = [perAttribute, part, '', '', '', '*','*', '*', '*', '*', '*', '*', '*']
    jStr = ":"

    sValue = slice_up(sValue)
    print(sValue)
    print(sValue[-1])

    if (sValue[-1] != sValue[0] and sValue[0].lower() != "apache"):
        # Fix for OpenSSH issues
        for a in sValue[-1]:
            if (a.isalpha()) == True:
                p1+=a
        if(p1 != "") :
            tmpV = sValue[-1]
            cpeArray[5] = p1 + tmpV[-1:]
            sValue[-1] = tmpV[:-2]

    if (len(sValue) == 1) :
        cpeArray[3] = sValue[0].lower()
    elif (len(sValue) == 2) :
        cpeArray[3] = sValue[0].lower()
        cpeArray[4] = sValue[-1].lower()
    elif (len(sValue) == 3) :
        cpeArray[2] = sValue[0].lower()
        cpeArray[3] = sValue[1].lower()
        cpeArray[4] = sValue[-1]

    cpeArray[3] = exceptions(cpeArray[4], cpeArray[3])

    if (cpeArray[3] == "sendmail" or cpeArray[3] == "wampserver") :
        cpeArray[2] = cpeArray[3]

    if (cpeArray[3] != "obfuscated") :
        cpe = jStr.join(cpeArray)

        print("Estimated CPE Generated: " + cpe)

        score = 0
        rCpe = ""

        f = open("cpedb.txt", "r")
        for cpeString in f:
            tmp = (fuzz.ratio(cpe, cpeString))
            if (tmp > score) :
                score = tmp
                rCpe = cpeString
        if (score > 86) :
            global curScore
            curScore = score
            print("Match: " + str(score) + "%")
            print("Real CPE picked: " + rCpe)
            cveDict = cve_lookup(rCpe.rstrip())
            return (cveDict)
        else :
            curScore = score
            return ("Undetected")
    else :
        curScore = 0
        return ("Obfuscated")


def exceptions (v, p):
    if (p == "iis") :
        p = "internet_information_server"
    if (p == "httpd") :
        p = "http_server"
    if (p == "httpapi") :
        p = "wampserver"
    if (p == "apache" or p == "nginx" or p == "ngi" or p == "nginxx" or p == "lighttpd") :
        if (v == '' or v == '*' or v == 'apache' or v == 'httpd' or v == 'nginx'):
            v = "http_server"
            print("**********************************************************************")
            print("WARNING - Detected potentially obfuscated banner")
            print("**********************************************************************")
        p = "obfuscated"
    return p

def slice_up(text):

    splitters = [" ", "/", "-", "..", ",", ";", "_"]

    if not any([x in text for x in splitters]):
        return [text]
    else:
        results = []
        for spliter in splitters:
            if spliter in text:
                for sp in text.split(spliter):
                    results.extend(slice_up(sp))

    return results


def addCVE (ip, cves, col, fieldName):

    db = client['flyby']
    col = db[col]
    col.find_one_and_update({"ip": ip},{"$set": {"cve_stats": "Statistical info here"}})
    col.find_one_and_update({"ip": ip},{"$set": {fieldName: cves}})

def scanStats (ip, col, stats, fieldName):

    db = client['flyby']
    col = db[col]
    col.find_one_and_update({"ip": ip},{"$set": {fieldName: stats}})
