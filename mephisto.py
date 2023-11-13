# -*- coding: UTF-8 -*-
__author__ = 'WILL_V'

from scf import SCF
from df import DF


class Malicious:
    local_path = ''
    remote_path = ''
    malicious_index = -1

    def __init__(self, local_path='', remote_path='', malicious_index=-1):
        self.local_path = local_path
        self.remote_path = remote_path
        self.malicious_index = malicious_index

    def traceSCF(self):
        scf = SCF(self.local_path)
        print("[+] Testing For Serverless Cloud Function")
        scf.traceback(index=self.malicious_index, remote_path=self.remote_path)

    def traceDF(self):
        df = DF(self.local_path)
        print("[+] Testing For Domain Fronting")
        df.traceback(index=self.malicious_index, remote_path=self.remote_path)

    def traceback(self, select='all'):
        print("[+] Start Tracing...")
        if select.lower() == 'scf':
            self.traceSCF()
        elif select.lower() == 'df':
            self.traceDF()
        elif select.lower() == 'all':
            self.traceSCF()
            self.traceDF()
        print("[+] Testing Finished.")
