# JA3 SSL Analysis
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
    2. If download unzip using- unzip JA3_SSL_Analysis.zip 
    3. cd JA3_SSL_Analysis
    4. sudo chmod 755 install.sh
    5. sudo ./install.sh
    
##### Note: A new field call JA3_desc will be added to the bro ssl.log file and will need to be mapped in Elasticsearch.  The script already adds the mapping to the logstash-template.json file, but Logstash will need to be restarted for the mappings to take effect.  This will cause a loss of logs while Logstash reinitializes! 

## Adding Kibana Dashboards
##### After Logstash has been restarted and initialized, Update the mappings in Kibana by selecting the Management link on the left pane then Index Patterns. In the filter type "ja3" then press enter.  If ja3_desc and ja3_desc.keyword do not appear press the refresh icon in the top right corner of the screen located next to the trash can icon.  If those fields do not appear, you may need to wait until the new daily index is created.  
##### Additional Kibana dashboards have been provided in the visualizations folder and can be imported in Kibana by selecting Management from the left pane then Saved Objects.  Select the Import icon in the top right of the screen and navigate to the JA3_Dashboard.json file.  Once the dashboard has been imported, Kibana will need to reinitialize and will be unresponsive for a minute or two.  
