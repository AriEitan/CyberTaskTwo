from __future__ import division
import socket
import subprocess
import re
import sys
import time
from optparse import OptionParser


def pingHost(ip_from_user):
    args = ["-n", 1, ip_from_user]
    ping = subprocess.Popen(["ping ", ip_from_user, "-n", "1", "-w", "100"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, error = ping.communicate()

    m = re.search('(\d+\.\d+\.\d+\.\d+)', out)
    if "100% loss" in out:
        return False, m.group(0)
    else:
        return True, m.group(0)

def networkScan(initialHost, interval=500):
    if interval < 0:
        interval = 0

    ipNumbers = initialHost.split(".", 4)
    for i in range(256):
        time.sleep(interval / 1000)
        ipNumbers[3] = str(i)
        success, ip = pingHost(".".join(ipNumbers))

        if success:
            print ip + " is up!"
        else:
            print ip + " is down!"

def portScanner(host, port, protocol):
    """

    :rtype : header string
    """
    if protocol.upper() == 'TCP':
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tcp.connect((host, port))
            if not port == 80:
                tcp.send("hello")
            else:
                tcp.send("GET / HTTP/1.0\r\n\r\n")

            result = tcp.recv(200)
        except Exception, e:
            result = e
        finally:
            tcp.close()

        return result


def bannerGrabbing(header, host, port):
    if header:
        try:
            #HTTP
            Server_linux = ['apache', 'nginx']
            X_Powered_By = ['php', 'asp']

            if port == 80:
                service_name = re.search(re.compile(r'^Server\:(.*)$', re.I | re.M), header)
                source_code = re.search(re.compile(r'^X-Powered-By\:(.*)$', re.I | re.M), header)
                print service_name.group(0)
                print source_code.group(0)
                if service_name.group(0):
                    print 'I found HTTP'
                    #Operation system banner
                    print "  Banner:", service_name.group(0)[8:]

                for service in Server_linux:
                    if service in service_name.group(0).lower():
                        print " ", host, "is Linux"
                    if 'iis' in service_name.group(0).lower():
                        print " ", host, "is Windows"

                    #Source code banner
                    for source in X_Powered_By:
                        if source_code.group(0):
                            print " Source:", source_code.group(0)[14:]
                            break
            elif port == 22:
                service_name = re.search(re.compile('SSH', re.I | re.M), header)
                print "I found: ", service_name.group(0)
            elif port == 21:
                service_name = re.search(re.compile('FTP', re.I | re.M), header)
                print "I found: ", service_name.group(0)
            elif port == 3306:
                service_name = re.search(re.compile('MySQL', re.I | re.M), header)
                print "I found: ", service_name.group(0)
        except Exception, e:
            return e
    else:
        print "[!] Error occured while grabbing the header"


def scanAllPorts(host, protocol, interval=500, bannerGrab=0):
    if interval < 0:
        interval = 0

    for i in range(80, 65535, 1):
        print "Attempting port No. %s:" % str(i)
        header = portScanner(host, i, protocol)
        if header is not None:
            if bannerGrab == "1":
                bannerGrabbing(header, host, i)
            else:
                print header
        time.sleep(interval / 1000)


def main(args):
    parser = OptionParser()
    parser.add_option("--ip", dest="targetHost", type="string", help="Enter target name or ip",
                      metavar="www.example.com")
    parser.add_option("-t", dest="interval", type="int", help="Time interval between each scan in milliseconds",
                      metavar="TIME_INTERVAL")
    parser.add_option("-p", dest="protocol", type="string", help="Returns the type of scan", metavar="[TCP/UDP/ICMP]")
    parser.add_option("--type", dest="scanType", help="The type of scan to execute [full,stealth,fin,ack]")
    parser.add_option("-b", dest="banner", help="Set to 1 for Banner Grabbing", metavar="[0,1]")
    parser.add_option("--command", dest="command", help="What do you wish to execute",
                      metavar="[port-scan, net-map, ping]")
    (options, args) = parser.parse_args()

    host = options.targetHost

    if host is None or options.command is None:
        parser.print_help()
    else:

        command = options.command

        if command == "ping":
            pingHost(host)
        elif command == "net-map":
            networkScan(host)
        elif command == "port-scan":
            protocol = options.protocol
            if protocol is None or protocol.lower() not in ["tcp", "udp", "icmp"]:
                parser.print_help()
                return

            scanAllPorts(host, protocol, options.interval, options.banner)

        elif command == "banner-grab":
            print ""
        else:
            parser.print_help()
            return

        #here we need to check what was asked of us
        #in the meantime we do network scan using ping
        #we assume ip is numeric already
        #        success, ip = pingHost(options.targethost)
        #       if success:
        #          print "Initial server is up!"
        #     else:
        #        print "Initial server is down!"
        #
        #       print "Commence network scanning"
        #
        #       if ip is not None:
        #          networkScan(ip, 700)


#checking another commit
if __name__ == "__main__":
    main(sys.argv[1:])