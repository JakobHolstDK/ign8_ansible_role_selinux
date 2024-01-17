import requests
import pprint
import os
import hashlib
import time
import json

# ignore ssl warnings
requests.packages.urllib3.disable_warnings()

def digest(mystring):
    # Create a SHA-256 hash object
    sha256 = hashlib.sha256()
    # Update the hash object with the bytes representation of the concatenated string
    sha256.update(mystring.encode('utf-8'))
    # Get the hexadecimal representation of the hash
    checksum = sha256.hexdigest()

    return checksum
def calculate_checksum(hostname, event, date, time):
    # Concatenate the variables into a single string
    data_to_hash = f"{hostname}{event}{date}{time}"

    # Create a SHA-256 hash object
    sha256 = hashlib.sha256()

    # Update the hash object with the bytes representation of the concatenated string
    sha256.update(data_to_hash.encode('utf-8'))

    # Get the hexadecimal representation of the hash
    checksum = sha256.hexdigest()

    return checksum

def alligndateformat(date):
    # the input date format is MM-DD-YYYY
    # the output date format is YYYY-MM-DD
    # this function converts it to YYYYMMDD
    # this is needed for the checksum
    mysplit = date.split('/')
    try:
        date = "%s-%s-%s" % (mysplit[2], mysplit[0], mysplit[1])
    except:
        date = None

    return date



def create_setrouble(entry):
    #url = 'https://selinuxapp01fl.unicph.domain/selinux/api/setroubleshoot/upload/'  # Replace with your API endpoint URL
    url = 'https://ignite.openknowit.com:/selinux/api/setroubleshoot/upload/'  # Replace with your API endpoint URL
    #test json string is in a file called testsetrouble.json
    response = requests.post(url, json=entry, verify = False)
    print(response.status_code)
    print(response.text)
    print(response.reason)
    if response.status_code == 201:
        print("Test event uploaded successfully.")
    else:
        if response.status_code == 200:
            print("Test event updated")
        else:
            print(f"Failed to upload test event. Status code: {response.status_code}")
            print(response.text)

def main():
    for file in os.listdir("/var/local/"):
        if "setroubleshoot" in file:
            #"open file and read it"
            openfile = open("/tmp/selinux/%s" % file, "r")
            jsonstring = openfile.read()
            openfile.close()
            #traverse file line by line
            jsonlines = jsonstring.splitlines()
            for line in jsonlines:
                line = line.replace("__CURSOR", "CURSOR")
                line = line.replace("__REALTIME_TIMESTAMP", "REALTIMETIMESTAMP")
                line = line.replace("__MONOTONIC_TIMESTAMP", "MONOTONICTIMESTAMP")
                line = line.replace("CODE_FILE", "CODEFILE")
                line = line.replace("CODE_FUNC", "CODEFUNC")
                line = line.replace("CODE_LINE", "CODELINE")
                line = line.replace("OBJECT_PID", "OBJECTPID")
                line = line.replace("SYSLOG_FACILITY", "SYSLOGFACILITY")
                line = line.replace("SYSLOG_IDENTIFIER", "SYSLOGIDENTIFIER")
                line = line.replace("_BOOT_ID", "BOOTID")
                line = line.replace("_CAP_EFFECTIVE", "CAPEFFECTIVE")
                line = line.replace("_CMDLINE", "CMDLINE")
                line = line.replace("_COMM", "COMM")
                line = line.replace("_EXE", "EXE")
                line = line.replace("_GID", "GID")
                line = line.replace("_MACHINE_ID", "MACHINEID")
                line = line.replace("_PID", "PID")
                line = line.replace("_SELINUX_CONTEXT", "SELINUXCONTEXT")
                line = line.replace("_SOURCE_REALTIME_TIMESTAMP", "SOURCEREALTIMESTAMP")
                line = line.replace("_SYSTEMD_CGROUP", "SYSTEMDCGROUP")
                line = line.replace("_SYSTEMD_INVOCATION_ID", "SYSTEMDINVOCATIONID")
                line = line.replace("_SYSTEMD_SLICE", "SYSTEMDSLICE")
                line = line.replace("_SYSTEMD_UNIT", "SYSTEMDUNIT")
                line = line.replace("_TRANSPORT", "TRANSPORT")
                line = line.replace("_UID", "UID")
                line = line.replace("_HOSTNAME", "HOSTNAME")
                line = line.replace("MESSAGE_ID", "MESSAGEID")

                

                myjson = json.loads(line)
                try: 
                    if myjson["CODEFILE"] is not None:
                        pass
                except:
                    myjson["CODEFILE"] = "unknown"
                try:
                    if myjson["CODEFUNC"] is not None:
                        pass
                except:
                    myjson["CODEFUNC"] = "unknown"
                try:
                    if myjson["CODELINE"] is not None:
                        pass
                except:
                    myjson["CODELINE"] = "unknown"
                try:
                    if myjson["UNIT"] is not None:
                        pass
                except:
                    myjson["UNIT"] = "unknown"
                try:
                    if myjson["INVOCATIONID"] is not None:
                        pass
                except:
                    myjson["INVOCATIONID"] = "unknown"
                try:
                    if myjson["SOURCEREALTIMETIMESTAMP"] is not None:
                        pass
                except:
                    myjson["SOURCEREALTIMETIMESTAMP"] = 0
                try:
                    if myjson["MEESSAGEID"] is not None:
                        pass
                except:
                    myjson["MESSAGEID"] = "unknown"
                try:
                    if myjson["SYSLOGFACILITY"] is not None:
                        pass
                except:
                    myjson["SYSLOGFACILITY"] = 0 
                try:
                    if myjson["PRIORITY"] is not None:
                        pass
                except:
                    myjson["PRIORITY"] = 0

                




                if myjson["MESSAGE"] is not None:
                    if "SELinux is preventing" in myjson["MESSAGE"]:
                        mydigest = digest(myjson["MESSAGE"])
                        myjson["digest"] = mydigest
                        create_setrouble(myjson)

                







                
if __name__ == '__main__':


    main()

