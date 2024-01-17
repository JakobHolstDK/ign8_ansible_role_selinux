import requests
import pprint
import os
import hashlib
import time

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


def create_event(eventdata):
    print("Creating test event...")
    url = 'https://selinuxapp01fl.unicph.domain/selinux/upload_selinux_event/'  # Replace with your API endpoint URL
    digest = calculate_checksum(eventdata['hostname'], eventdata['event'], eventdata['date'], eventdata['time'])
    test_event = {
        "digest": digest,
        "hostname": eventdata['hostname'],
        "event": eventdata['event'],
        "date": alligndateformat(eventdata['date']),
        "time": eventdata['time'],
        "serial_num": eventdata['serial_num'],
        "event_kind": eventdata['event_kind'],
        "session": eventdata['session'],
        "subj_prime": eventdata['subj_prime'],
        "subj_sec": eventdata['subj_sec'],
        "subj_kind": eventdata['subj_kind'],
        "action": eventdata['action'],
        "result": eventdata['result'],
        "obj_prime": eventdata['obj_prime'],
        "obj_sec": eventdata['obj_sec'],
        "obj_kind": eventdata['obj_kind'],
        "how": eventdata['how']
    }
    response = requests.post(url, json=test_event, verify = False)
    if response.status_code == 201:
        print("Test event uploaded successfully.")
    else:
        if response.status_code == 200:
            print("Test event updated")
        else:
            print(f"Failed to upload test event. Status code: {response.status_code}")
            print(response.text)

def main():
    # the event data is csv files in /tmp/selinux
    # the event data is in the format:
    # hostname,event,date,time,serial_num,event_kind,session,subj_prime,subj_sec,subj_kind,action,result,obj_prime,obj_sec,obj_kind,how
    # hostname is the hostname of the server
    # event is the event text

    # read the csv file
    files = os.listdir('/tmp/selinux')
    for file in files:
        if file.endswith('.csv'):
            #the hostname is the first part of the filename dashweb01fl.unicph.domain.sealert.csv
            hostname = file.split('.sealert.csv')[0]
            with open("/tmp/selinux/" + file)  as f:
                for line in f:
                    myitem = line.split(',')
                    eventdata = {
                        "hostname": hostname,
                        "event": myitem[1],
                        "date": myitem[2],
                        "time": myitem[3],
                        "serial_num": myitem[4],
                        "event_kind": myitem[5],
                        "session": myitem[6],
                        "subj_prime": myitem[7],
                        "subj_sec": myitem[8],
                        "subj_kind": myitem[9],
                        "action": myitem[10],
                        "result": myitem[11],
                        "obj_prime": myitem[12],
                        "obj_sec": myitem[13],
                        "obj_kind": myitem[14],
                        "how": myitem[15]
                    }
                    if myitem[11] != 'success':
                        print(eventdata)
                        create_event(eventdata)
                    
                    # create a dictionary with the event data
                    # call create_event with the dictionary as argument
                    pass

    # for each line in the file
    # create a dictionary with the event data
    # call create_event with the dictionary as argument

    # wait 5 seconds
    # repeat
                
if __name__ == '__main__':
    main()

