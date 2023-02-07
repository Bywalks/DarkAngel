#!/usr/bin/env python3
# coding=utf-8

"""
Example
"""

import os
import sys
from oneforall import OneForAll


def oneforall(domain):
    test = OneForAll(target=domain)
    test.dns = True
    test.brute = True
    test.req = True
    test.takeover = True
    test.run()
    results = test.datas
    print(results)


if __name__ == '__main__':
    #oneforall('freebuf.com')
    test = "https://matomo.cloud/"
    #print(os.path.dirname(os.path.abspath(__file__)))
    print(len(test.split("/")))
