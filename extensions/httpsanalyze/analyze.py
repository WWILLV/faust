# -*- coding: UTF-8 -*-
__author__ = 'WILL_V'

# import scapy
from scapy_ssl_tls.ssl_tls import *


class Https_analyze:
    path = ''
    pktl = []

    def __init__(self, path):
        self.path = path
        self.pktl = self.pcap_load()

    def pcap_load(self):
        if os.path.exists(self.path):
            return rdpcap(self.path)
        else:
            raise Exception("pcap file not found")

    def show_packet(self, index):
        pkt = self.pktl[index]
        pkt.show()

    def get_certificate_host(self, index):
        pkt = self.pktl[index]
        pkt.show()
        pkt.summary()
        print(pkt['SSL/TLS']['TLS Handshakes']['TLS Client Hello']['TLS Extension Servername Indication'][
                  'TLS Servername'].data)
        return index

    def search_client_hello(self, searchlist):  # 在start到end范围内搜索client_hello
        try:
            for i in searchlist:
                pkt = self.pktl[i]
                try:
                    if pkt['SSL/TLS']['TLS Handshakes']['TLS Handshake'].type == 1:
                        return i
                except:
                    continue
            return -1
        except Exception as e:
            return 'ERROR' + e.message

    def get_client_hello_host(self, index):  # 获取client_hello host
        try:
            pkt = self.pktl[index]
            if pkt['SSL/TLS']['TLS Handshakes']['TLS Handshake'].type == 1:
                client_hello_host = \
                    pkt['SSL/TLS']['TLS Handshakes']['TLS Client Hello']['TLS Extension Servername Indication'][
                        'TLS Servername'].data
            else:
                client_hello_host = ''
            return client_hello_host
        except Exception as e:
            return 'ERROR:' + e.message


if __name__ == '__main__':
    ha = Https_analyze(r'/home/nsab2022/wwz/malicious/yunhttps.pcap')
    # index = ha.search_client_hello(0, 30)
    index=5
    print ha.get_client_hello_host(index)

