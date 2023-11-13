# -*- coding: UTF-8 -*-
__author__ = 'WILL_V'

import json
import re
import os
import urllib.parse
import urllib.request
import dns.resolver
from extensions.conn import callback as apicall
from scapy.all import *
from scapy.utils import PcapReader
from scapy.layers.tls import *
from socket import gethostbyname
from whois import whois


class API:
    # action_list = ['client_hello_host','certificate_host']
    apidict = {"path": "", "action": "", "parm": {}, "msg": ""}

    def __init__(self, path="", action="", parm=None, msg=""):
        if parm is None:
            parm = {}
        self.apidict = {"path": path, "action": action, "parm": parm, "msg": msg}

    def get_api(self):
        return self.apidict

    def get_result(self, apidict=None):
        if apidict is None:
            apidict = self.apidict
        if apidict == {"path": "", "action": "", "parm": {}, "msg": ""}: apidict = self.apidict
        cb = apicall(apidict)
        if cb.startswith("ERROR:"):
            raise Exception(cb.lstrip("ERROR:"))
        return cb


class Source:  # Get Source

    def __init__(self):
        pass

    # Check if the ip/domain/url is from a cloud server
    def is_Cloud(self, ip=None, domain=None, url=None):
        CloudList = ['Tencent', "Alibaba", "Baidu", "Google", "Cloudflare"]
        if ip:
            if not re.compile(r"((?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d))").findall(ip):
                raise Exception("IP Error")
            with urllib.request.urlopen("https://api.ip.sb/geoip/" + ip) as rep:
                response = json.loads(rep.read().decode())
                try:
                    if response['isp']:
                        for cloud in CloudList:
                            if cloud.lower() in response['isp'].lower():
                                return True
                        return False
                    else:
                        return False
                except KeyError:
                    return False
        elif domain:
            fip = gethostbyname(domain)
            return self.is_Cloud(ip=fip)
        elif url:
            fip = gethostbyname(str(urllib.parse.urlparse(url).hostname))
            return self.is_Cloud(ip=fip)
        else:
            raise Exception("No IP or domain input.")

    # Get the CNAME of the domain/url
    def get_cname(self, domain=None, url=None):
        if domain:
            domain_cname = []
            try:
                CNAME = dns.resolver.resolve(domain, 'CNAME')
            except dns.resolver.NoAnswer:
                print(
                    "NoAnswer: The DNS response does not contain an answer to the question: %s. IN CNAME" % domain)
                return None
            for i in CNAME.response.answer:
                for j in i.items:
                    domain_cname.append(j.to_text())
            return domain_cname
        elif url:
            return self.get_cname(domain=str(urllib.parse.urlparse(url).hostname))
        else:
            raise Exception("No domin input")

    # Check if domain is serverless cloud function
    def is_serverless(self, domain=None):
        funcList = [".apigw.tencentcs.com"]
        for func in funcList:
            if domain.endswith(func):
                return True
        return False

    # Serverless cloud function domain and service provider matching
    def match_serverless(self, domain=None):
        matchDict = {".apigw.tencentcs.com": "Tencent"}
        if self.is_serverless(domain):
            ends = ""
            for d in range(len(domain) - 1, -1, -1):
                ends = domain[d] + ends
                if ends in matchDict:
                    return matchDict[ends]
            return None

    # CNAME-based CDN matching
    def match_CDN(self, cname=None, CNAMEList=None):
        matchCDNDict = {"cdn.dnsv1.com": "Tencent", "alicdn.com": "Alibaba",
                        "akamai.net": "Akamai", "fastly.net": "Fastly"}
        if cname:
            if cname.endswith('.'):
                cname = cname[:-1]
            ends = ""
            for d in range(len(cname) - 1, -1, -1):
                ends = cname[d] + ends
                if ends in matchCDNDict:
                    return matchCDNDict[ends]
            return None
        elif CNAMEList:
            matchList = []
            for cname in CNAMEList:
                matchList.append(self.match_CDN(cname=cname))
            return matchList

    # Check if domain/url using CDN (Based on CNAME)
    def is_CDN(self, domain=None, url=None):
        if domain:
            cdnlist = self.match_CDN(CNAMEList=self.get_cname(domain=domain))
            if cdnlist is None:
                return False
            return cdnlist != []
        elif url:
            return self.is_CDN(domain=str(urllib.parse.urlparse(url).hostname))
        else:
            raise Exception("No domain input")

    def get_whois(self, domain=None):
        if domain is None: return None
        if re.match(
                "^(((\d)|([1-9]\d)|(1\d{2})|(2[0-4]\d)|(25[0-5]))\.){3}((\d)|([1-9]\d)|(1\d{2})|(2[0-4]\d)|(25[0-5]))$",
                domain):
            return None
        return whois(url=domain)

    def parse_whois(self, whois=None):
        whois_dict = dict()
        if whois is None:
            return None
        if "domain_name" in whois: whois_dict["domain_name"] = whois["domain_name"]
        if "registrar" in whois: whois_dict["registrar"] = whois["registrar"]
        if "name_servers" in whois: whois_dict["name_servers"] = whois["name_servers"]
        if "emails" in whois: whois_dict["emails"] = whois["emails"]
        if "org" in whois: whois_dict["org"] = whois["org"]
        if "name" in whois: whois_dict["name"] = whois["name"]
        return whois_dict


class Parse:  # PCAP File Parse
    packetlist = None
    sessions = None
    Response = None

    def __init__(self):
        self.Response = collections.namedtuple('Response', ['header', 'payload'])

    def is_http(self, packet):  # Check if packet is HTTP
        if packet.haslayer('TCP'):
            if packet['TCP'].dport == 80 or packet['TCP'].sport == 80:
                return True

    def is_https(self, packet):  # Check if packet is HTTPS
        if packet.haslayer('TCP'):
            if packet['TCP'].dport == 443 or packet['TCP'].sport == 443:
                return True

    def pcap_load(self, path=""):  # Load pcap file and return PacketList
        if os.path.exists(path):
            self.packetlist = rdpcap(path)
            self.sessions = self.packetlist.sessions()
            return self.packetlist
        else:
            raise FileNotFoundError("pcap file not found")

    def get_header(self, payload):  # Get HTTP Header from payload
        try:
            header_raw = payload[:payload.index(b'\r\n\r\n') + 2]  # 切片前包后不包,+2 是为了将分隔数据行的'\r\n'也含进去
        except ValueError:
            # sys.stdout.write('-')
            sys.stdout.flush()
            return None

        header = json.dumps(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n', header_raw.decode()))
        if 'Content-Type' not in header:
            return None
        return header

    def get_responses(self, dport=80, sport=80):  # Get HTTP Response
        responses = list()
        for session in self.sessions:
            payload = b''
            for packet in self.sessions[session]:
                try:
                    if packet['TCP'].dport == dport or packet['TCP'].sport == sport:
                        payload += bytes(packet['TCP'].payload)
                except IndexError:
                    # sys.stdout.write('x')
                    sys.stdout.flush()

            if payload:
                header = self.get_header(payload)
                if header is None:
                    continue
                responses.append(self.Response(header=header, payload=payload))
        return responses

    def get_host(self, packet):  # Get Host from packet
        if packet.haslayer('TCP'):
            if packet.haslayer('Raw'):
                if packet['TCP'].dport == 80 or packet['TCP'].sport == 80:
                    if re.findall(r'\r\nHost: (.*?)\r\n', packet['Raw'].load.decode()):
                        return packet['Raw'].load.decode().split('\r\n')[1].split(': ')[1]
                elif packet['TCP'].dport == 443 or packet['TCP'].sport == 443:
                    if re.findall(r'\r\nHost: (.*?)\r\n', packet['Raw'].load.decode()):
                        return packet['Raw'].load.decode().split('\r\n')[1].split(': ')[1]
                else:
                    return None

    def get_packet(self, packetslist=None, index=-1):  # Get Packet
        if packetslist is None:
            packetslist = []
        return packetslist[index]

    def get_clienthello(self, path="", index=-1):  # Get Client Hello Host
        api = API(path=path, action="client_hello_host", parm={"index": index}, msg="get client hello host")
        # print(api.get_api())
        return api.get_result()

    def search_clienthello(self, path="", searchlist=None):  # search Client Hello
        if searchlist is None:
            searchlist = []
        api = API(path=path, action="search_client_hello", parm={"searchlist": searchlist}, msg="search client hello")
        # print(api.get_api())
        return api.get_result()

    def get_httpheader(self, packet):  # Get HTTP Header from packet
        headerlist = []
        # scapy.all.load_layer("http")
        if packet.haslayer('TCP'):
            self.get_responses(self.get_session(packet))
        else:
            return []
        resps = self.get_responses()
        for resp in resps:
            headerlist.append(resp.header)
        # print(headerlist)
        return headerlist

    def get_srcIP(self, packet):  # Get Source IP
        return packet['IP'].src

    def get_destIP(self, packet):  # Get Destination IP
        return packet['IP'].dst

    def filter_ip(self, packetlist=None, srcIP="", destIP="", ip=""):  # Filter IP
        if packetlist is None:
            packetlist = []
        indexlist = []
        for i in range(len(packetlist)):
            if packetlist[i].haslayer('IP'):
                if srcIP != "" and destIP != "":
                    if packetlist[i]['IP'].src == srcIP and packetlist[i]['IP'].dst == destIP:
                        indexlist.append(i)
                        continue
                elif srcIP != "" and destIP == "":
                    if packetlist[i]['IP'].src == srcIP:
                        indexlist.append(i)
                        continue
                elif destIP != "" and srcIP == "":
                    if packetlist[i]['IP'].dst == destIP:
                        indexlist.append(i)
                        continue
                elif ip != "":
                    if packetlist[i]['IP'].src == ip or packetlist[i]['IP'].dst == ip:
                        indexlist.append(i)
                        continue
                else:
                    continue
        return indexlist

    def get_session(self, packet=None):  # Get Session from packet
        if packet is None:
            raise Exception("No packet input")
        if packet.haslayer('TCP'):
            return packet['TCP'].sport, packet['TCP'].dport
        return None

    def filter_session(self, packerlist=None, sport=-1, dport=-1):  # Filter Session
        if packerlist is None:
            packerlist = []
        indexlist = []
        for i in range(len(packerlist)):
            if packerlist[i].haslayer('TCP'):
                if packerlist[i]['TCP'].sport == sport or packerlist[i]['TCP'].dport == dport:
                    indexlist.append(i)
        return indexlist

    def get_XAPI(self, header=""):  # Get XAPI from HTTP Header
        xapi = {"X-Api-ID": "", "X-Api-RequestId": "", "X-Request-Id": "", "X-Api-FuncName": "", "X-Api-ServiceId": "",
                "X-Api-HttpHost": ""}
        hdic = json.loads(header)
        for h in hdic:
            if h[0] in xapi:
                xapi[h[0]] = h[1]
        if xapi["X-Api-ID"] == "":
            return None
        return xapi


if __name__ == '__main__':
    pass
