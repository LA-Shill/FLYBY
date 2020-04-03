<h1 align="center">FLYBY🛩️</h1>
<h4 align="center">Passive Reconnaissance and Vulnerability Assessment Platform</h1>
<p align="center">
  <a href="https://github.com/LA-Shill/FLYBY/blob/master/LICENSE">
    <img alt="License: GNU V3" src="https://img.shields.io/badge/License-GNU_V3-4e73df.svg" target="_blank"/>
  </a>
  <a href="https://twitter.com/LA-Shill">
    <img alt="Twitter: LA-Shill" src="https://img.shields.io/twitter/follow/LA-Shill.svg?style=social" target="_blank" />
  </a>
</p>
<p align="center">
  <a href="https://github.com/LA-Shill/FLYBY">
    <img src="https://i.ibb.co/8KSQSK0/flyby.png" alt="FLYBY">
  </a>
  <p align="center">
    FLYBY is a open source web based passive reconnaissance and vulnerability assessment platform which utilising scan data from the <a href="https://censys.io/">Censys</a> network to identify known vulnerabilities. All vulnerability data is pulled from the <a href="https://nvd.nist.gov/">National Vulnerability Database (NVD)</a> which is maintained by the U.S. government.
    </p>
    <p align="center">
      The FLYBY platform has been developed as part of my penultimate year Ethical Hacking mini-project at Abertay University.

</p>

## Table of Contents

* [Getting Started](#getting-started)
  * [Dependencies](#dependencies)
  * [Installation (Linux)](#installation)
* [Usage](#usage)
  * [Launching](#startup)
  * [Features](#features)
* [Contributing](#contributing)
* [License](#license)

## Getting Started
<p align="center">
FLYBY comes as both a standalone <strike>command line</strike> application as well as a web based application. The application relies on numerous dependencies and requires a valid <a href="https://censys.io/api">Censys</a> account API key.
</p>

### Dependencies

* Python 3.6 or later
* MongoDB 2.2 or later
* Redis Server
* Pip3
  * Flask
  * Flask-PyMongo
  * Censys
  * Fuzzywuzzy
  * PyMongo
  * Requests
  * Redis
  * RQ (Redis Queue)



### Installation

1. Install and start [MongoDB](https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/)

```bash
# Install mongodb
sudo apt-get install -y mongodb-org

# Start mongodb service
sudo systemctl start mongod
```

2. Install [cve-search](https://github.com/cve-search/cve-search) and populate MongoDB (timely process . . .)  
_note **cve-search** is designed to work on **Linux only** - However can be adapted for **Windows**, get in touch if you need a hand._

```bash
# Install dependencies
sudo pip3 install -r requirements.txt

# Create and populate CVEDB in MongoDB
./sbin/db_mgmt_cpe_dictionary.py -p

# then . . patience . .
./sbin/db_mgmt_json.py -p

# then . . . patience is seriously a virtue . . .
./sbin/db_updater.py -c
```

3. Install and start [redis](https://redis.io/) server

```bash
# Install Redis Server
sudo apt install redis-server

# Start the Redis Server
sudo systemctl start redis
```

4.  Install FLYBY 🛩️

```bash
# Download repo
git clone https://github.com/LA-Shill/FLYBY.git

# Access directory
cd Flyby

# Install dependencies
pip3 install -r requirements.txt
```

## Usage
### Startup
1. Create a worker
```bash
# Start RQ worker (redis)
rq worker
```
2. Start the development server
```bash
# Start dev web server on 127.0.0.1:5000
python3 app.py
```

3. Navigate to FLYBY in your browser of choice at: [127.0.0.1:5000](http://127.0.0.1:5000)
<a href="https://twitter.com/LA-Shill">
  <img alt="Twitter: LA-Shill" src="https://i.ibb.co/dLnM3wc/search.png" target="_blank" />
</a>

4. Finally add your Censys API key by navigating to the settings tab located at: [127.0.0.1:5000/settings](http://127.0.0.1:5000/settings)
<a href="https://twitter.com/LA-Shill">
  <img alt="Twitter: LA-Shill" src="https://i.ibb.co/JpLY6qk/Capture.png" target="_blank" />
</a>

5. 🛩️🧨 Happy scanning! 💥️🦠

### Features
Working on it  . . .

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[GNU V3](https://github.com/LA-Shill/FLYBY/blob/master/LICENSE)
