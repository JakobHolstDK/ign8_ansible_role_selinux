#!/usr/bin/env bash
SESTATUSFILE="/var/local/sestatus.json"
SEALERTFILE="/var/local/sealerts.csv"
SEALERTARCHIVE="/var/local/sealerts.tar.gz"
SEALERTS="/var/local/sealerts"
SETROUBLESHOOTFILE="/var/local/setroubleshoot.json"
SESTSTATUSBFILE="/var/local/sestatusb.json"

journalctl  -u setroubleshootd.service  --output json --since "1 month ago"  > $SETROUBLESHOOTFILE

for id in $(journalctl  -u setroubleshootd.service  --output json|jq . |grep "For complete SELinux messages run:" |awk -F'sealert -l ' '{print $2 }' |awk -F'"' '{ print $1 }')
do
    if [[ -f $SEALERTS.$id ]];
    then
        echo "File $SEALERTS.$id exists."
    else
        echo "File $SEALERTS.$id does not exist."
        sealert -l $id  > $SEALERTS.$id
    fi
done
tar cf $SEALERTARCHIVE $SEALERTS.*
sestatus -b > $SESTSTATUSBFILE 



EPOCH=$(date +%s)
HOSTNAME=$(hostname)
SESTATUS=$(sestatus)
GETENFORCE=$(getenforce)

ausearch -ts this-month --format csv   >  $SEALERTFILE


STATUS=$(echo $SESTATUS | awk -F"SELinux status:" '{ print $2 }' |awk '{ print $1 }')
MOUNT=$(echo $SESTATUS | awk -F"SELinuxfs mount:" '{ print $2 }' |awk '{ print $1 }')
ROOTDIR=$(echo $SESTATUS | awk -F"SELinux root directory:" '{ print $2 }' |awk '{ print $1 }')
POLICYNAME=$(echo $SESTATUS | awk -F"Loaded policy name: " '{ print $2 }' |awk '{ print $1 }')
CURRENTMODE=$(echo $SESTATUS | awk -F"Current mode:" '{ print $2 }' |awk '{ print $1 }')
MODEFROMFILE=$(echo $SESTATUS | awk -F"Mode from config file:" '{ print $2 }' |awk '{ print $1 }')
MLSSTATUS=$(echo $SESTATUS | awk -F"Policy MLS status:" '{ print $2 }' |awk '{ print $1 }')
POLICYDENYUNKNOWN=$(echo $SESTATUS | awk -F"Policy deny_unknown status:" '{ print $2 }' |awk '{ print $1 }')
MEMPROTECT=$(echo $SESTATUS | awk -F"Memory protection checking:" '{ print $2 }' |awk '{ print $1 }')
MAXKERNEL=$(echo $SESTATUS | awk -F"Max kernel policy version:" '{ print $2 }' |awk '{ print $1 }')





TOTAL=$(cat $SEALERTFILE | wc -l)
SUCCESS=$(cat $SEALERTFILE | awk -F';' '{ print $6 }' |grep -c "success")
FAILED=$(cat $SEALERTFILE | awk -F';' '{ print $6 }' |grep -c "failed")

printf "[\n"  > $SESTATUSFILE
printf "  {\n" >> $SESTATUSFILE
printf "    \"status\": \"%s\"," $STATUS >> $SESTATUSFILE
printf "    \"mount\": \"%s\"," $MOUNT >> $SESTATUSFILE
printf "    \"rootdir\": \"%s\"," $ROOTDIR >> $SESTATUSFILE
printf "    \"policyname\": \"%s\"," $POLICYNAME >> $SESTATUSFILE
printf "    \"currentmode\": \"%s\"," $CURRENTMODE >> $SESTATUSFILE
printf "    \"modefromfile\": \"%s\"," $MODEFROMFILE >> $SESTATUSFILE
printf "    \"mlsstatus\": \"%s\"," $MLSSTATUS >> $SESTATUSFILE
printf "    \"policydenyunknown\": \"%s\"," $POLICYDENYUNKNOWN >> $SESTATUSFILE
printf "    \"memprotect\": \"%s\"," $MEMPROTECT >> $SESTATUSFILE
printf "    \"maxkernel\": \"%s\"," $MAXKERNEL >> $SESTATUSFILE
printf "    \"total\": \"%s\"," $TOTAL >> $SESTATUSFILE
printf "    \"success\": \"%s\"," $SUCCESS >> $SESTATUSFILE
printf "    \"failed\": \"%s\"" $FAILED >> $SESTATUSFILE
printf "\n  }\n"  >> $SESTATUSFILE
printf "]\n" >> $SESTATUSFILE


ls -l $SEALERTFILE
ls -l $SESTATUSFILE
