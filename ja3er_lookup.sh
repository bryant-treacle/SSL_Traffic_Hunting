#!/bin/bash
if [ "$1" = "--help" ]; then
echo "usage: ja3er_lookup.sh  [input file ] [output file]"
else
while IFS= read -r line; do
  curl -X GET "https://ja3er.com/search/$line" >> "$2"  && echo "ja3_hash: $line" >> "$2"
done < "$1"
fi
