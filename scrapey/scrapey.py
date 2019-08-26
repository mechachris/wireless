from argparse import ArgumentParser
import sys
import os
import subprocess
import csv
import time
#from scapey.all import *

mac_vendors = "./mac_vendors.txt"

aps = {}
bssid_list = []

ap_list_dic = {}
ap_list = []

APs = []
client_list = []

def color(txt, code = 1, modifier = 0):

    return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def sniffAP(p):
    if ( (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp))
                 and not aps.has_key(p[Dot11].addr3)):
        ssid       = p[Dot11Elt].info
        bssid      = p[Dot11].addr3
        channel    = int( ord(p[Dot11Elt:3].info))
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

        # Display discovered AP
        if ssid == args.essid and bssid not in bssid_list:
            print color("[+] Found BSSID " + str(bssid) + " on channel " + str(channel) + " with name " + str(ssid), 2,1)
            bssid_list.append(bssid)
            ap_list_dic["bssid"] = str(bssid)
            ap_list_dic["channel"] = str(channel)
            ap_list.append({'bssid':str(bssid),'channel':str(channel)})

def channel_hop(args):

    bg_chans = [1, 7, 13, 2, 8, 3, 9, 4, 10, 5, 11, 6, 12]
    #bg_chans = [7, 3, 12]

    a_chans = [
        36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,
        60,  62,  64,  100, 102, 104, 106, 108, 110, 112, 114, 116,
        118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142,
        144, 149, 151, 153, 155, 157, 159, 161, 165, 169, 173, 0
        ]

    # The following two if statements allow setting the nominated interface to monitor mode. You'll need to figure out the full interface name
    # for this one. macOS is usually en0 but can be en8 on older Macs with monitor mode. Keep in mind 2018 and 2019 MacBooks might have issues
    # due to a dodgy wireless driver.
    
    if args.band == "2.4":
        print "Scanning on 2.4 Ghz"
        for channel in bg_chans:
            print "Trying channel: " + str(channel)
            #sys.stdout.write('\rTrying channel: %d' %channel)
            #sys.stdout.flush()
            if "Darwin" in subprocess.check_output("uname -a", shell=True):
                os.system("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport %s sniff %d" % (args.interface, channel)) #macOS specific
            else:
                os.system("iw dev %s set channel %d" % (args.interface, channel)) #Linux, Unix, Universal
            time.sleep(1)
            sniff(iface=args.interface,prn=sniffAP,timeout=int(args.timeout))

    elif args.band == "5":
        print "Scanning on 5 Ghz"
        for channel in a_chans:
            print "Trying channel: " + str(channel)
            if "Darwin" in subprocess.check_output("uname -a", shell=True):
                os.system("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport %s sniff %d" % (args.interface, channel)) #macOS specific
            else:
                os.system("iw dev %s set channel %d" % (args.interface, channel)) #Linux, Unix, Universal
            time.sleep(1)
            sniff(iface=args.interface,prn=sniffAP,timeout=int(args.timeout))

def get_vendor_mac(bss):
    file = open(mac_vendors, 'r')
    for line in file.read().splitlines():
        t = line.split("~")[0]
        if t.split(":")[:3] == bss.split(":")[:3]:
            return line.split("~")[1].rstrip("\n")

    return " Unknown"

def sniffSTA(pkt):

    if pkt.haslayer(Dot11Beacon):
        bss = pkt.getlayer(Dot11).addr2.upper()
        if bss not in APs:
            APs.append(bss)

    elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L and not pkt.haslayer(EAPOL):
        # This means it's data frame.
        sn = pkt.getlayer(Dot11).addr2.upper()
        rc = pkt.getlayer(Dot11).addr1.upper()

        for entry in ap_list:

            if sn == entry["bssid"].upper():
                if rc not in client_list:
                    print color("[+] Found connected client " + str(rc) + get_vendor_mac(rc), 2,1)
                    client_list.append(rc)
                    os.system("echo '%s~%s~%s~%s' >> deauth.txt" % (entry["channel"],entry["bssid"],rc,get_vendor_mac(rc)))
                    os.system("echo '%s' >> scope.txt" % (get_vendor_mac(sn)))

            elif rc == entry["bssid"].upper():
                if sn not in client_list:
                    print color("[+] Found connected client " + str(sn) + get_vendor_mac(sn), 2,1)
                    client_list.append(sn)
                    os.system("echo '%s~%s~%s~%s' >> deauth.txt" % (entry["channel"],entry["bssid"],sn,get_vendor_mac(sn)))
                    os.system("echo '%s' >> scope.txt" % (get_vendor_mac(sn)))

def find_clients(args):

    for entry in ap_list:
        print "Finding clients connected to " + str(entry["bssid"]) + " on channel " + str(entry["channel"])
        os.system("iw dev %s set channel %d" % (args.interface, int(entry["channel"])))
        time.sleep(1)
        sniff(iface=args.interface,prn=sniffSTA,timeout=int(args.timeout))

def main():

    parser = ArgumentParser()
    parser.add_argument("-e", "--essid", dest="essid", required=True,
                        help="ESSID to search for")

    parser.add_argument("-i", "--interface", dest="interface", required=True,
                        help="Wireless interface for access point (should not be managed by Network Manager)")

    parser.add_argument("-b", "--band", dest="band", required=True,
                         help="Wireless band to listen on (values are 2.4 or 5)")

    parser.add_argument("-t", "--timeout", dest="timeout", required=True,
                         help="Time to wait before hoping between channels and access points")

    global args
    args = parser.parse_args()
    
    while True:
        channel_hop(args)
        find_clients(args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[+] Interrupt received, stopping...")
        exit()
