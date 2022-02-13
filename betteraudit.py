#!/bin/python

import requests, argparse, json, urllib3, os
from enum import Enum
from datetime import datetime

VERSION = 1.0
BANNER = f"""
  _______       __   __              _______          __ __ __   
 |   _   .-----|  |_|  |_.-----.----|   _   .--.--.--|  |__|  |_ 
 |.  1   |  -__|   _|   _|  -__|   _|.  1   |  |  |  _  |  |   _|
 |.  _   |_____|____|____|_____|__| |.  _   |_____|_____|__|____|
 |:  1    \                         |:  |   |                    
 |::.. .  /                         |::.|:. |                    
 `-------'                          `--- ---'                    
 """

ERROR_BANNER = """
▄██████████████▄▐█▄▄▄▄█▌
██████▌▄▌▄▐▐▌███▌▀▀██▀▀
████▄█▌▄▌▄▐▐▌▀███▄▄█▌
▄▄▄▄▄██████████████▀
"""

HELP = """
   >> help <<
show (aps,hids)
write (aps,hids)
write clients SSID
"""

# Suppress SSL warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Arguments 
parser = argparse.ArgumentParser(description='Interface with the bettercap API.')
parser.add_argument('ip', help='Location of bettercap.')
parser.add_argument('-u', '--user', help='API basic auth username')
parser.add_argument('-p', '--pw', help='API basic auth password')
args = parser.parse_args()

# Functionality
def welcome():
    # Do init call
    response = requests.get (f'https://{args.ip}:8083/api/session', auth=(args.user, args.pw), verify=False)
    session = json.loads(response.text)
    print(BANNER,end='')
    print(f"BetterAudit v{VERSION}\tBettercap v{session['version']}")

def bettercap_stat():
    response = requests.get (f'https://{args.ip}:8083/api/session', auth=(args.user, args.pw), verify=False)
    session = json.loads(response.text)
    print(f"StartedAt: {session['started_at']}")
    print(f"PolledAt: {session['polled_at']}")
    print(f"CPUs: {session['resources']['cpus']}")
    for iface in session['interfaces']:
        print(f"\nInterface:\t{iface['name']}")
        try:
            print(f"  -IPv4: {iface['addresses'][0]['address']}")
        except Exception: pass
        print(f"  -MAC: {iface['mac']}")
        print(f"  -Flags: {iface['flags']}")
    print()

#TODO
def get_caplets():
    pass

def ShowLAN():
    response = requests.get (f'https://{args.ip}:8083/api/session/lan', auth=(args.user, args.pw), verify=False)
    lan = json.loads(response.text)
    for host in lan['hosts']:
        print(f"\nHostname: {host['hostname']}")
        print(f"IPv4: {host['ipv4']}")
        print(f"MAC: {host['mac']}")
    print()

def WriteLAN():
    response = requests.get (f'https://{args.ip}:8083/api/session/lan', auth=(args.user, args.pw), verify=False)
    lan = json.loads(response.text)
    out_csv = open(f"LAN_{datetime.now()}.csv", 'w')
    out_csv.write('IP Address,Hostname,MAC')
    for host in lan['hosts']:
        out_csv.write(f"\n{host['ipv4']},{host['hostname']},{host['mac']}")
    print()
    out_csv.close()

#TODO
def gps():
    pass

def WriteAPs():
    response = requests.get (f'https://{args.ip}:8083/api/session/wifi', auth=(args.user, args.pw), verify=False)
    wifi = json.loads(response.text)
    out_csv = open(f"AccessPoints_{datetime.now()}.csv", 'w')
    out_csv.write('Key Material Captured,SSID,MAC Address,Encryption,Cipher,Authentication,Channel,Vendor,First_Seen,Last_Seen')
    for ap in wifi['aps']:
        out_csv.write(f"\n{ap['handshake']},{ap['hostname'].replace(',','')},{ap['mac']},{ap['encryption']},{ap['cipher']},{ap['authentication']},{ap['channel']},{ap['vendor'].replace(',','')},{ap['first_seen']},{ap['last_seen']}")
    out_csv.close()

def ShowAPs():
    response = requests.get (f'https://{args.ip}:8083/api/session/wifi', auth=(args.user, args.pw), verify=False)
    wifi = json.loads(response.text)
    for ap in wifi['aps']:
        print(f"\nSSID: {ap['hostname']}")
        print(f"Clients: {len(ap['clients'])}")
        print(f"Handshake: {ap['handshake']}")
    print()

def ShowHIDs():
    response = requests.get (f'https://{args.ip}:8083/api/session/hid', auth=(args.user, args.pw), verify=False)
    hids = json.loads(response.text)
    #open('hids.json', 'w').write(str(hid))
    for hid in hids['devices']:
        print(f"\nType: {hid['type']}")
        print(f"Address: {hid['address']}")
        print(f"Channels: {str(hid['channels'])}")
    print()

def WriteHIDs():
    response = requests.get (f'https://{args.ip}:8083/api/session/hid', auth=(args.user, args.pw), verify=False)
    hids = json.loads(response.text)
    out_csv = open(f"HIDs_{datetime.now()}.csv", 'w')
    out_csv.write('Address,Type,Channels')
    for hid in hids['devices']:
        out_csv.write(f"\n{hid['address']},{hid['type']},{str(hid['channels']).replace(',','')}")
    print()

def WriteClients(ssid):
    response = requests.get (f'https://{args.ip}:8083/api/session/wifi', auth=(args.user, args.pw), verify=False)
    wifi = json.loads(response.text)
    for ap in wifi['aps']:
        if ap['hostname'].lower().__contains__(ssid):
            out_csv = open(f'{ap["hostname"]}_Clients_{datetime.now()}.csv', 'w')
            out_csv.write('Hostname,IPv4 Address,MAC Address,Vendor,First_Seen,Last_Seen')
            for client in ap['clients']:
                out_csv.write(f"\n{client['hostname']},{client['ipv4']},{client['mac']},{client['vendor']},{client['first_seen']},{client['last_seen']}")
    out_csv.close()


# Command Parsing
def prompt():
    cmd = input("-> ").lower()

    # banner
    if cmd == 'banner':
        print(BANNER)

    # help
    elif cmd == 'help':
        print(HELP)

    # info
    elif cmd == 'info':
        bettercap_stat()

    elif cmd == 'exit' or cmd == 'bye':
        exit()
    
    # ! (shell escape)
    elif cmd.__contains__('!'):
        os.system(cmd.replace('!',''))

    # write ...
    elif cmd.__contains__('write '):
        tmp=cmd.split(' ')
        cmd=tmp

        # aps
        if cmd[1] == 'aps':
            WriteAPs()

        # clients
        elif cmd[1] == 'clients':
            WriteClients(cmd[2])
        
        # aps
        if cmd[1] == 'lan':
            WriteLAN()

        # hids
        elif cmd[1] == 'hids':
            WriteHIDs()

    # show ...
    elif cmd.__contains__('show '):
        tmp=cmd.split(' ')
        cmd=tmp

        # aps
        if cmd[1] == 'aps':
            ShowAPs()

        # lan
        elif cmd[1] == 'lan':
            ShowLAN()
              
        # hids
        elif cmd[1] == 'hids':
            ShowHIDs()
        else: print('Bad Syntax')

    
    else: print('try \'help\'')


# Run a loop
welcome()
while True:
    try:
        prompt()
    except Exception as e:
        print(ERROR_BANNER)
        print(e)