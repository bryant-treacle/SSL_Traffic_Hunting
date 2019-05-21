from datetime import datetime
from elasticsearch import Elasticsearch
import time
es = Elasticsearch()

while True:
#####################################################
# Create an empty table to place the unique results #
#####################################################
    CN_NAME_UNIQUE = []

#############################################################
# Elasticsearch Query to get All Common Names for SSL Certs #
#############################################################
    CN_NAME_SEARCH = es.search(index="*:logstash-*", body={"query": {"bool": {"must": [{"term" : {"event_type": "bro_ssl"}}], "filter": [{ "range": {"@timestamp": {"gte": "now-1h", "lte": "now"}}}]}}}, filter_path=['hits.hits._source.certificate_common_name'], size=10000)

#Example of the returned results {u'hits': {u'hits': [{u'_source': {u'certificate_common_name': u'sls.update.microsoft.com'}}]}}, Consists of a Dictionary, nested in a list, nested in a dictionary.'''

# Extract the results of the first dictionary to get the list of results 
    CN_NAME_LIST_1 = CN_NAME_SEARCH.get('hits', {}).get('hits')

# Iterate through the resulting list to extract the remaining values
    for CN_NAME_DIC_1 in CN_NAME_LIST_1:
        CN_NAME_DIC_2 = CN_NAME_DIC_1.get('_source', {}).get('certificate_common_name')

# Only want the top level domain from the results.  Spliting the string, select the last two fields then join them with a '.'
        CN_NAME_SPLIT = CN_NAME_DIC_2.split(".")[-2:]
        CN_NAME = '.'.join(CN_NAME_SPLIT) 
        if CN_NAME not in CN_NAME_UNIQUE:
            CN_NAME_UNIQUE.append(CN_NAME)
# Send a query to elasticsearch bro_dns for a dns_request to the TLD of the SSL CN field.
# Add the wildcard to the beginning of the script.
            CN_NAME_WILDCARD = ("*") + CN_NAME

##############################################################
# Search Elasticsearch to get the UID to pass to bro_notices #
##############################################################
            SSL_SEARCH_UID = es.search(index="*:logstash-*", body={"query": {"bool": {"must": [{"wildcard" : {"certificate_common_name": CN_NAME_WILDCARD}}], "filter": [{ "range": {"@timestamp": {"gte": "now-2h", "lte": "now"}}}]}}}, filter_path=['hits.hits._source.uid'], size=1)
            SSL_SEARCH_LIST_1 = SSL_SEARCH_UID.get('hits', {}).get('hits')
	    #Convert to a sting inorder to search for the word None.  Issue: Python cannot iterate over a null value (returned as "None"
            SSL_SEARCH_UID_STR = str(SSL_SEARCH_LIST_1)
            if "None" not in SSL_SEARCH_UID_STR:
                for SSL_SEARCH_DIC_1 in SSL_SEARCH_LIST_1:
                    SSL_UID = SSL_SEARCH_DIC_1.get('_source', {}).get('uid')                   

##############################################################################################################################################  
# Search Elasticsearch bro_dns records for a query containing the Parent.TLD domain refenrenced in the CN field name of the SSL Certificate. #
##############################################################################################################################################
            DNS_PARENT_DOMAIN_SEARCH = es.search(index="*:logstash-*", body={"query": {"bool": {"must": [{"wildcard" : {"query.keyword": CN_NAME_WILDCARD}}], "filter": [{ "range": {"@timestamp": {"gte": "now-2h", "lte": "now"}}}]}}}, filter_path=['hits.hits._source.uid'], size=1)

# Change the list to a string and seach for the string uid.  Uid is only present in records that return a match
            DNS_PARENT_DOMAIN_SEARCH_STR = str(DNS_PARENT_DOMAIN_SEARCH.get('hits', {}).get('hits'))
            if 'uid' not in  DNS_PARENT_DOMAIN_SEARCH_STR:
                print("No DNS query found for", CN_NAME) 

###############################
# Send results to Bro_notices #
###############################           
                es.index(index='logstash-bro-2019.05.21', doc_type='doc', body={"source_port": 443, "port": 443, "host": "-", "syslog-sourceip": "127.0.0.1", "protocol": "tcp", "sub_msg": "CN=securityonion", "peer_description": "-", "event_type": "bro_notice", "syslog-tags": ".source.s_bro_notice", "uid": SSL_UID, "p": 443, "syslog-facility": "-", "logstash_time": 0.0, "destination_ip": "127.0.0.1", "destination_ips": "-", "syslog-host": "-", "note": "SSL::No_DNS_Query_for_Cert_CN", "@timestamp": "2019-05-21T15:08:40.288Z", "dropped": "false", "message": "-}", "timestamp": "2019-05-21T15:08:40.288Z", "tags": ["syslogng", "bro", "internal_destination", "internal_source"], "msg": "Common Name Field has no DNS query for the parent domain.", "ips": ["-","-"], "destination_port": 443, "source_ips": "-", "action": ["Notice::ACTION_LOG"], "@version": "1", "source_ip": "127.0.0.1", "syslog-file_name": "cn_analysis.py", "syslog-host_from": "-", "suppress_for": 3600, "syslog-priority": "notice"})
    time.sleep(600)
