from multiprocessing.connection import Client
import sys

address = ('localhost', 6000)
conn = Client(address)
conn.send({"domain_sid" : sys.argv[1], "username" : sys.argv[2], "challenge" : sys.argv[3], "response" : sys.argv[4]})
conn.close()
