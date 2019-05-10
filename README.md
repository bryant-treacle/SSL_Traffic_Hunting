# JA3 SSL Analysis
This script will add additional analytics and visualizations for JA3 SSL hashes to Security Onion 16.04.x  

####     Adds addtional Meta-data to JA3 Client Hash by including a lookup table in Bro
![alt text](https://github.com/bryant-treacle/Repository_images/blob/master/JA3_Client_Hashes.png)

####     Adds a blacklist of known malicious SSL JA3 hashes from https://sslbl.abuse.ch to the Zeek/Bro Intel framework.
![alt text](https://github.com/bryant-treacle/Repository_images/blob/master/JA3_Freq_Analysis.png)


## Usage:
    This script contains all necessary additional deb packages required for STIG compliance.  
    1. Download or Clone the Repo
    2. If download unzip using *unzip JA3_SSL_Analysis*
    3. cd JA3_SSL_Analysis
    4. sudo chmod 755 install.sh
    5. sudo ./install.sh
    
