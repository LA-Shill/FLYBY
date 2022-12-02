# !/usr/bin/env python
# Name:     app.py
# By:       Liam Shillinglaw
# Date:     24.02.2020
# Version   0.2
# -----------------------------------------------

# Import External Libraries
from flask import Flask, render_template, redirect, url_for, request
from flask_pymongo import PyMongo
from rq import Queue, Worker
import re
import redis

# Import Custom External Libraries
from censysScan import censys_grab, getConfig, setConfig, createCpeDB, stats,cpeDBCheck, cveDBCheck, vulScan

# Initialise Flask Instance
app = Flask(__name__)

# Initialise Redis & Task Queue Instances
r = redis.Redis()
q = Queue(default_timeout=86400, connection=r)

# Connect to MongoDB
mongo = PyMongo(app, uri="mongodb://localhost:27017/flyby")

# Censys Route
@app.route('/censys', methods=['POST'])
def censysScan():
    # Add IPv4 + CIDR Validation + Serverside required check
    ipRange = request.form.get("search")

    apis = [request.form.get('criminalipAPI'), request.form.get('censysAPI'), request.form.get('shodanAPI')]
    options = [request.form.get('httpService'), request.form.get('httpsService'), request.form.get('ftpService'), request.form.get('sshService'), request.form.get('smtpService')]
    ip = re.sub(r'[/]', "_", ipRange)
    colNames = mongo.db.list_collection_names()
    if (ip in colNames):
        return redirect(url_for('index'))
    else:
        censys_grab(ipRange, apis, options)
        return redirect(url_for('dataCol', col=ip))

# Home Route
@app.route('/', methods=['GET'])
def index():
    try:
        response = r.client_list()
        workers = Worker.all(connection=r)
        workers = Worker.all(queue=q)
        if(len(workers) > 0):
            worker = workers[0]
            state = worker.state
            if(len(q) == 0 and state == "busy"):
                scanStatus = "<div class=\"text-center\"><h3 class=\"text-success font-weight-bold m-0\">Scanning<br></h3> <span class=\"text-xs\">Time started: " + str(worker.birth_date) + "</span><br>"
            elif(len(q) > 0):
                scanStatus = "<div class=\"text-center\"><h3 class=\"text-success font-weight-bold m-0\">Scanning<br></h3> <span class=\"text-xs\">Time started: " + str(worker.birth_date) + "</span><br>"
            else:
                scanStatus = "<div class=\"text-center\"><h3 class=\"text-info font-weight-bold m-0\">No scans in the queue<br></h3>"
        else:
            scanStatus = "<div class=\"text-center\"><h3 class=\"text-danger font-weight-bold m-0\">No workers available<br></h3>"
    except redis.ConnectionError:
        scanStatus = "<div class=\"text-center\"><h3 class=\"text-danger font-weight-bold m-0\">Redis service not available<br></h3>"

    data = mongo.db.list_collection_names()
    tScanned = 0
    sScanned = 0
    tVulns = 0
    tVulns1 = 0
    for col in data:
        tVulns += (mongo.db[col].find({'cve_stats': {"$exists": True}}).count())
        sScanned += (mongo.db[col].find({'cve_stats': {"$exists": False}}).count())
        tVulns1 += (mongo.db[col].find({'http_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'ftp_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'https_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'ssh_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'snmp_cves': {"$exists": True}}).count())
        tScanned += (mongo.db[col].count())

    totalStats = {'tScanned': tScanned, 'sSystems': sScanned, 'tVulnerable': tVulns, 'tVulnerabilities': tVulns1}
    return render_template('index.html', stats=totalStats, jobs=q.jobs, scanStatus=scanStatus)

# Emtpy Task Route
@app.route('/clearscans', methods=['POST'])
def delQue():
    q.empty()
    return redirect(url_for('index'))

# Systems Info Route
@app.route('/data/', methods=['GET'])
def data():
    data = mongo.db.list_collection_names()
    tCount = {}
    for col in data:
        tCount[col] = (mongo.db[col].count())
    return render_template('systems.html', systems=data, total=tCount)

# Scans Info Route
@app.route('/scan/', methods=['GET'])
def scan():
    data = mongo.db.list_collection_names()
    return render_template('scan.html', systems=data)

# System Info Route
@app.route('/data/<string:col>', methods=['GET'])
def dataCol(col):
    data = mongo.db[col].find({})
    if (mongo.db[col].count() != 0):
        return render_template('data.html', systems=data)
    else:
        return render_template("404.html")

# Vulnerability Scan Info Route
@app.route('/scan/<string:col>', methods=['GET'])
def vulRScan(col):
    if (mongo.db[col].count() != 0):
        task = q.enqueue(vulScan, col)
        return redirect(url_for('index'))
    else:
        return render_template("404.html")

# Systems Vulnerability Info Route
@app.route('/vulns', methods=['GET'])
def vulns():
    data = mongo.db.list_collection_names()
    tCount = {}
    vCount = {}
    for col in data:
        vCount[col] = (mongo.db[col].find({'cve_stats': {"$exists": True}}).count())
        #vCount[col] = (mongo.db[col].find({'http_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'ftp_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'https_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'ssh_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'snmp_cves': {"$exists": True}}).count())
        tCount[col] = (mongo.db[col].count())

    return render_template('vulns.html', systems=data, tStats=tCount, vStats=vCount)

# System Vulnerability Info Route
@app.route('/vulns/<string:col>', methods=['GET'])
def vulnsView(col):
    data = mongo.db[col].find({})
    if (mongo.db[col].count() != 0):
        return render_template('data_vulns.html', systems=data)
    else:
        return render_template("404.html")

# System Vulnerability Graph Route
@app.route('/vulns/<string:col>/stats', methods=['GET'])
def vulStats(col):

    tVulnerable = (mongo.db[col].find({'cve_stats': {"$exists": True}}).count())
    sSystems = (mongo.db[col].find({'cve_stats': {"$exists": False}}).count())
    totalServices = (mongo.db[col].find({'ftp': {"$exists": True}}).count()) + (mongo.db[col].find({'ssh': {"$exists": True}}).count()) + (mongo.db[col].find({'https': {"$exists": True}}).count()) + (mongo.db[col].find({'http': {"$exists": True}}).count()) + (mongo.db[col].find({'snmp': {"$exists": True}}).count())
    tVulns1 = (mongo.db[col].find({'http_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'ftp_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'https_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'ssh_cves': {"$exists": True}}).count()) + (mongo.db[col].find({'snmp_cves': {"$exists": True}}).count())
    tScanned = (mongo.db[col].count())
    sServices = totalServices - tVulns1

    ftpT = (mongo.db[col].find({'ftp': {"$exists": True}}).count())
    sshT = (mongo.db[col].find({'ssh': {"$exists": True}}).count())
    httpsT = (mongo.db[col].find({'https': {"$exists": True}}).count())
    httpT = (mongo.db[col].find({'http': {"$exists": True}}).count())
    snmpT = (mongo.db[col].find({'snmp': {"$exists": True}}).count())
    serviceInfo = [ftpT, sshT, httpT, httpsT, snmpT]

    vftpT = (mongo.db[col].find({'ftp_cves': {"$exists": True}}).count())
    vsshT = (mongo.db[col].find({'ssh_cves': {"$exists": True}}).count())
    vhttpsT = (mongo.db[col].find({'https_cves': {"$exists": True}}).count())
    vhttpT = (mongo.db[col].find({'http_cves': {"$exists": True}}).count())
    vsnmpT = (mongo.db[col].find({'snmp_cves': {"$exists": True}}).count())
    vserviceInfo = [vftpT, vsshT, vhttpT, vhttpsT, vsnmpT]

    totalStats = {'col': col, 'tScanned': tScanned, 'sSystems': sSystems, 'tVulnerable': tVulnerable, 'tVulnerabilities': tVulns1, 'tServices': totalServices, 'sServices': sServices, 'sepServices': serviceInfo, 'vSepServices': vserviceInfo}
    return render_template('stats.html', stats=totalStats)

# Settings Route
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    data = getConfig()
    censys = stats()
    cpeCheck = cpeDBCheck()
    cveCheck = cveDBCheck()
    return render_template('settings.html', settings=data, censysInfo=censys, cpe=cpeCheck, cve=cveCheck)

# Vulnerability Info Route
@app.route('/settings/censys', methods=['POST'])
def settingsCensys():
    if (request.method == 'POST'):
        u = request.form.get("uid")
        s = request.form.get("secret")
        setConfig(u, s)
    return redirect(url_for('settings'))


@app.route('/settings/cpedb', methods=['POST'])
def settingCPE():
    createCpeDB()
    return redirect(url_for('settings'))


if __name__ == "__main__":
    app.run(debug=True)
