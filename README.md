# JA3 SSL Analysis
This script will add additional analytics and visualizations for JA3 SSL hashes to Security Onion 16.04.x  

Adds addtional Meta-data to JA3 Client Hash by including a lookup table in Bro
![alt text](https://github.com/bryant-treacle/Repository_images/blob/master/JA3_Client_Hashes.png)

Add a blacklist of known malicious SSL JA3 hashes from https://sslbl.abuse.ch to the Zeek/Bro Intel framework.
Place Image here

Provides additoal Dashboards in Kibana for visualization and analysis of JA3 hashes
Place Image here

## Usage:
    This script contains all necessary additional deb packages required for STIG compliance.  
    1. Download or Clone the Repo
    2. If download unzip using *unzip JA3_SSL_Analysis*
    3. cd JA3_SSL_Analysis
    4. sudo chmod 755 install.sh
    5. sudo ./install.sh
    
