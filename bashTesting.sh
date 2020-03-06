#!/bin/bash
# A simple copy script

# Experimenting with adding a variable
ATTACHMENTS=()


#LIST=(1 2 3)
#for i in "${LIST[@]}"; do
#for i in $LIST do
#	ATTACHMENTS+=(LIST[i])
#done
#

echo $ATTACHMENTS

# Checking program
LIST=(1 2 3)
if [[ "${#LIST[@]}" -gt 4 ]];then 
 echo "example.$i"
fi



echo $0

if [[ -n $OSTYPE ]]; then
	echo String is greater than zero
	exit 1
fi
