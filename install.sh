#!/bin/bash
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
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
JA3_INSTALL_LOCATION=$(find /opt/ -type d -name "ja3")
echo "Updating JA3.bro to include a lookup_table for JA3 Client Hashses."
cp files/ja3.bro $JA3_INSTALL_LOCATION/
cp files/ja3_lookup.dat $JA3_INSTALL_LOCATION/

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
