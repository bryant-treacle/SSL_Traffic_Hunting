# SSL Traffic Hunting 
##### This Repo contains several scripts that helps you identify malicious SSL Traffic in Security Onion 16.04.x.  Below is a description of the different tools.
    1. JA3_SSL_Analysis
    2. ELastalert JA3 Blacklist for Know bad JA3 Hashes
    3. Elastalert JA3 Whitelist to identify Hashes that deviate from Baseline
    4. ssl_cn_lookup.py
    5. ja3er_lookup.sh

## JA3 SSL Analysis
This script will add additional analytics and visualizations for JA3 SSL hashes to Security Onion 16.04.x  

####     Adds additional Meta-data to JA3 Client Hash by including a lookup table in Bro
![alt text](https://github.com/bryant-treacle/Repository_images/blob/master/JA3_Freq_Analysis.png)
![alt text](https://github.com/bryant-treacle/Repository_images/blob/master/JA3_Client_Hashes.png)

####     Adds a blacklist of known malicious SSL JA3 hashes from https://sslbl.abuse.ch to the Zeek/Bro Intel framework.
![alt text](https://github.com/bryant-treacle/Repository_images/blob/master/JA3_Intel.png)
![alt text](https://github.com/bryant-treacle/Repository_images/blob/master/JA3_Baseline_%26_Intel.png)


## Installation:
    This script is designed to be applied to Security Onion 16.04.5.x and above.  
    1. Download or Clone the Repo
    2. If download unzip using- unzip SSL_Traffic_Hunting-master.zip 
    3. cd SSL_Traffic_Hunting-master
    4. sudo chmod 755 install.sh
    5. sudo ./install.sh
    
##### Note: A new field call JA3_desc will be added to the bro ssl.log file and will need to be mapped in Elasticsearch.  The script already adds the mapping to the logstash-template.json file, but Logstash will need to be restarted for the mappings to take effect.  This will cause a loss of logs while Logstash reinitializes! 

## Adding Kibana Dashboards:
##### After Logstash has been restarted and initialized, Update the mappings in Kibana by selecting the Management link on the left pane then Index Patterns. In the filter type "ja3" then press enter.  If ja3_desc and ja3_desc.keyword do not appear press the refresh icon in the top right corner of the screen located next to the trash can icon.  If those fields do not appear, you may need to wait until the new daily index is created.  
##### Additional Kibana dashboards have been provided in the visualizations folder and can be imported in Kibana by selecting Management from the left pane then Saved Objects.  Select the Import icon in the top right of the screen and navigate to the JA3_Dashboard.json file.  Once the dashboard has been imported, Kibana will need to reinitialize and will be unresponsive for a minute or two.  

## Elastalert rule for known bad ja3 hashes
##### An Elastalert blacklist rule has been created based on the known malicous JA3 hashes located in the sslbl.abuse.ch/ja3-fingerprints/ Database.  This rule has the same effect as adding the list to the Bro intel.dat file, but may be easier to manage/deploy over a large sensor grid.  To use the blacklist, copy the following files to the /etc/elastalert/rules folder:  
    - ja3_known_bad_blacklist.yaml
    - ja3_known_bad_blacklist.txt
##### Note: To add additional hashes to the blacklist append the hash to the bottom of the ja3_known_bad_blacklist.txt file.    

## Elastalsert rule for whitelisting client JA3 Hashes
##### An Elastalert whitelist rule has been provied to help baseline(whitelist) the known GOOD client JA3 hashes.  This technique is great for detecting anomolies in SSL traffic within your organization.  To use the whitelist, add all known good hashes to the ja3_baseline_whitelist.txt file, and move following files to the /etc/elastalert/rules folder: 
    - ja3_baseline_whitelist.yaml
    - ja3_baseline_whitelist.txt

## ssl_cn_to_dns_lookup.py
##### This script will take the value of the certificate common name and queries elasticsearch for a dns query that matches the Parent + Top Level Domain ie. google.com.  Although rfc 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile only requires a string, the overwhelming best business practice by the internet CA's is to place the FQDN server name in that field. Example (.iot.us-east-1.amazonaws.com). Many malicous payloads use Domain Generating Algorithms (DGAs) or throw-away domains as their C2 and either randomly generate a values for this field (Metasploit) or continue using the same certificate that was registered against a previous domain.

##### Prerequisites
    This script requires the elasticsearch python client to be installed.  Below are the instructions.
    1. curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py"
    2. sudo python get-pip.py
    3. pip install elasticsearch

##### This script is meant to be ran continually and can be set as a cron job to start at reboot with normal user privilages.  It must reside on the Master if no Storage Nodes are utilized or ONLY the Storage Nodes if utilized.  It will write the results to Elasticsearch and will be visible in the Bro Notices dashboard with the following notice type: SSL::No_DNS_Query_for_Cert_CN.
    useage: python ssl_cn_lookup.py
    To run in background use: nohup python ssl_cn_lookup.py &

## ja3er_lookup.sh:
##### This scipt can be used to check your unknown ja3 hashes against an online repository.  
    usage: ja3er_lookup.sh [input file] [output file]
    inputfile - A list of ja3 hashes (1 per line)
    outputfile - The name and location you want the output to be saved to
    
