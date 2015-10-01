import sys
import optparse
import socket
from socket import *

def connScan(tgtHost, tgtPort):
  try:
    connSkt = socket(AF_INET, SOCK_STREAM)
    connSkt.connect((tgtHost, tgtPort))
    print '[+] %d/tcp open'% tgtPort
    connSkt.close()
  except:
    print '[-] %d/tcp closed'% tgtPort

def portScan(tgtHost, tgtPorts):
  try:
    tgtIP = gethostbyname(tgtHost)
  except:
    print "[-] Cannot resolve '%s': Unknown host" %tgtHost
    return
  try:
    tgtName = gethostbyaddr(tgtIP)
    print '[+] Scan Results for: ' + tgtName[0]
  except:
    print '[+] Scan Results for: ' + tgtIP
  setdefaulttimeout(1)
  for tgtPort in tgtPorts:
    if (tgtPort > 1) or (tgtPort < 65536):
       #print 'Scanning port ' + tgtPort
       connScan(tgtHost, int(tgtPort))


def main():
  parser = optparse.OptionParser("usage%prog "+\
    "-H <target host> -p <target port>")
  parser.add_option('-H', dest='tgtHost', type='string', \
    help='specify target host')
  parser.add_option('-p', dest='tgtPort', type='string', \
    help='specify target port[s] separated by comma')
  (options, args) = parser.parse_args()
  if (options.tgtHost == None) or (options.tgtPort == None):
     print '[-] You must specify a target host and port[s].'
     print '[-] Usage: python testport.py -H <target host> -p <target port>'
     exit(0)
  tgtHost = options.tgtHost
  #print 'options.tgtPort' + sys.argv[4]

  tgtPorts = options.tgtPort.split(',')
  #for port in tgtPorts:
    #print 'target ports ' + port

  portScan(tgtHost,tgtPorts)

if __name__ == '__main__':
   main()
