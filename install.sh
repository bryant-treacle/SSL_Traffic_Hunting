#!/bin/bash

# Purpose:  This script will install additional JA3 Analytics components for Security Onion 16.04
# Author: Bryant Treacle
# Date: 10 May 2019


####################
#  Welcome Script  #
####################
welcome_script()
{
echo "This script will install additional JA3 Analytics components for Security Onion 16.04.  Would you like to continue? (Y/n)"
read user_continue_prompt

if [ ${user_continue_prompt,,} != "y" ] ; then
    echo -e "\e[31mExiting script!\e[0m"
    exit
fi
}

#################
#  JA3_intel    #
#################
JA3_intel()
{
echo "Updating JA3.bro to include a lookup_table for JA3 Client Hashses."
cp files/ja3.bro /opt/bro/share/bro/ja3/

echo "Updating logstash-template in /etc/logstash to include additional field mappings."
cp files/logstash-template.json /etc/logstash

echo "Adding Known Malicious JA3 Hashes to Bro intel.dat."
cat files/intel.dat >> /opt/bro/share/bro/intel/intel.dat

echo "Restarting Bro for changes to take effect."
so-bro-restart
}

############################
#  Where the Magic Happens #
############################
welcome_script
JA3_intel
