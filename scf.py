# -*- coding: UTF-8 -*-
__author__ = 'WILL_V'

# Serverless Cloud Function

import traffic_analyzer as ta


class SCF:
    pcap_path = ''
    packetlist = None
    par = None

    def __init__(self, pcap_path='') -> None:
        self.pcap_path = pcap_path
        self.par = ta.Parse()
        self.packetlist = self.par.pcap_load(pcap_path)

    def check_source(self, index=-1):
        source = ta.Source()
        par = ta.Parse()
        pkt = par.get_packet(self.packetlist, index)
        srcIP = par.get_srcIP(pkt)
        destIP = par.get_destIP(pkt)
        if source.is_Cloud(ip=srcIP):
            return srcIP
        elif source.is_Cloud(ip=destIP):
            return destIP
        else:
            return None

    def ipfilter(self, ip):
        par = ta.Parse()
        return par.filter_ip(self.packetlist, ip=ip)

    def match_serverless(self, host):
        source = ta.Source()
        match = source.is_serverless(domain=host)
        if match:
            print("[-] Serverless Cloud Service Match: %s" % source.match_serverless(domain=host))
        return match

    def trace_http(self, indexlist=None):
        if indexlist is None:
            indexlist = []
        par = self.par
        source = ta.Source()
        header = []
        for i in indexlist:
            pkt = self.packetlist[i]
            tempheader = par.get_httpheader(pkt)
            if header != tempheader:
                header = tempheader
                print(f"[+] Found HTTP Header(%d)" % (len(header)))

            xapiflag = False
            # pkt.show()
            if par.get_host(pkt) is not None:
                host = par.get_host(pkt)
                print(f"[+] Found Host: {host}")
                self.match_serverless(host)
                whois = source.get_whois(domain=host)
                if whois is not None:
                    pw = source.parse_whois(whois)
                    print(f"[-] Found Whois: {pw}")
                break
            for head in header:
                xapi = par.get_XAPI(header=head)
                if xapi is not None:
                    print(f"[+] Found X-API {xapi}")
                    shost = xapi['X-Api-HttpHost']
                    print(f"[+] Found Host: {shost}")
                    self.match_serverless(shost)
                    xapiflag = True
                    self.match_serverless(shost)
                    whois = source.get_whois(domain=shost)
                    if whois is not None:
                        pw = source.parse_whois(whois)
                        print(f"[-] Found Whois: {pw}")
                    break
            if xapiflag:
                break

            # if len(header)==0:
            #     continue
            # else:
            #     xapiflag=False
            #     # pkt.show()
            #     if par.get_host(pkt)!=None:
            #         host=par.get_host(pkt)
            #         print(f"[+] Found Host: {host}")
            #         self.match_serverless(host)
            #     for head in header:
            #         xapi=par.get_XAPI(header=head)
            #         if xapi!=None:
            #             print(f"[+] Found X-API {xapi}")
            #             shost=xapi['X-Api-HttpHost']
            #             print(f"[+] Found Host: {shost}")
            #             self.match_serverless(shost)
            #             xapiflag=True
            #             break
            #     if xapiflag:break

    def trace_https(self, indexlist=None, remote_path=''):
        if indexlist is None:
            indexlist = []
        par = ta.Parse()
        if remote_path == '':
            remote_path = self.pcap_path
        chi = int(par.search_clienthello(remote_path, searchlist=indexlist))
        if chi == -1:
            return None
        chh = par.get_clienthello(path=remote_path, index=chi)
        if chh != '':
            print(f"[+] Found Client Hello Host: {chh}")
            self.match_serverless(chh)
            source = ta.Source()
            whois = source.get_whois(domain=chh)
            if whois is not None:
                pw = source.parse_whois(whois)
                print(f"[-] Found Whois: {pw}")
        else:
            print("[-] No Client Hello Host Found")

    def traceback(self, index=-1, remote_path=''):
        ip = self.check_source(index)
        if ip is None:
            raise Exception("No cloud source found")
        par = self.par
        hflag = par.is_http(self.packetlist[index])
        print(f"[+] Found Cloud Service: {ip} (%s)" % ("HTTP" if hflag else "HTTPS"))
        self.packetlist = self.packetlist[:index]
        iplists = self.ipfilter(ip)[::-1]
        print("[+] Traceback (Total %d):" % len(iplists))
        if hflag:
            self.trace_http(iplists)
        else:
            self.trace_https(iplists, remote_path=remote_path)


if __name__ == '__main__':
    pass
