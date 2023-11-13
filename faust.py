# -*- coding: UTF-8 -*-
__author__ = 'WILL_V'

from sys import argv


class Faust:
    evil = None

    def __init__(self, local_path='', remote_path='', malicious_index=-1):
        from mephisto import Malicious as Mep
        self.evil = Mep(local_path=local_path, remote_path=remote_path, malicious_index=malicious_index)

    def traceback(self, select='all'):
        self.evil.traceback(select=select)


def test():
    print("云函数http测试：")
    faust = Faust(local_path="", remote_path="", malicious_index=100)
    faust.traceback(select='scf')
    print("\n云函数https测试：")
    faust = Faust(local_path="", remote_path="", malicious_index=100)
    faust.traceback(select='scf')
    print("\n域前置http测试：")
    faust = Faust(local_path="", remote_path="", malicious_index=100)
    faust.traceback(select='df')
    print("\n域前置https测试：")
    faust = Faust(local_path="", remote_path="", malicious_index=210)
    faust.traceback(select='df')


def main(local_path, remote_path, malicious_index, select):
    faust = Faust(local_path=local_path, remote_path=remote_path, malicious_index=malicious_index)
    faust.traceback(select=select)


if __name__ == '__main__':
    guide_test = r"""
___________                      __   
\_   _____/____   __ __  _______/  |_ 
 |    __) \__  \ |  |  \/  ___/\   __\
 |     \   / __ \|  |  /\___ \  |  |  
 \___  /  (____  /____//____  > |__|  
     \/        \/           \/        
    """
    guide_test += ("\nUsage: python faust.py malicious_index local_path select_type(option, default as all) "
                   "remote_path(option)\n")
    print(guide_test)
    local_path = ''
    remote_path = ''
    malicious_index = -1
    select = 'all'
    if len(argv) < 3:
        exit()
    malicious_index = argv[1]
    local_path = argv[2]
    if len(argv) > 3:
        select = argv[3]
        if len(argv) > 4:
            remote_path = argv[4]
    main(local_path, remote_path, malicious_index, select)
