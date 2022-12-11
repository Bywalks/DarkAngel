# !/usr/bin/env python
# -*-coding:utf-8 -*-

# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks

import time
import subprocess
from IPy import IP

def cmdprocess(cmdline):
    pipe = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, stderr = pipe.communicate()
    return_code = pipe.returncode
    stderr = stderr.decode(errors='replace')
    output = output.decode(errors='replace')
    return output, stderr, return_code

def get_vul_type(scan_item):
    vul_name = scan_item.get('name')
    if not vul_name:
        return
    vul_name = vul_name.lower()
    if len(vul_name.split('/')) > 2:
        vul_type = vul_name.split('/')[0]
    elif vul_name.find('弱口令') >= 0 or vul_name.find('未授权') >= 0 or vul_name.find('登录绕过') >= 0:
        vul_type = '弱口令'
    elif vul_name.find('泄露') >= 0 or vul_name.find('文件读') >= 0:
        vul_type = 'baseline'
    elif vul_name.find('xss') >= 0:
        vul_type = 'xss'
    elif vul_name.find('sql') >= 0:
        vul_type = 'sql-injection'
    elif vul_name.find('json') >= 0 or vul_name.find('序列化') >= 0:
        vul_type = 'jsonp/fastjson'
    elif vul_name.find('struts') >= 0:
        vul_type = 'struts'
    elif vul_name.find('thinkphp') >= 0:
        vul_type = 'thinkphp'
    elif vul_name.find('traversal') >= 0 or vul_name.find('穿越') >= 0:
        vul_type = 'path-traversal'
    elif vul_name.find('redirect') >= 0 or vul_name.find('跳转') >= 0:
        vul_type = 'redirect'
    elif vul_name.find('dirscan') >= 0 or vul_name.find('目录') >= 0 or vul_name.find('枚举') >= 0:
        vul_type = 'dirscan'
    elif vul_name.find('upload') >= 0 or vul_name.find('文件写') >= 0 or vul_name.find('文件上传') >= 0:
        vul_type = 'upload'
    elif vul_name.find("cmd-injection") != -1 or vul_name.find("rce") != -1 or vul_name.find("代码") != -1 or\
            vul_name.find("执行") != -1:
        vul_type = 'cmd-injection'
    elif vul_name.find('poc') >= 0 or vul_name.find('cve') != -1 or vul_name.find("phantasm") != -1 or\
            vul_name.find('漏洞') >= 0:
        vul_type = 'cve'
    else:
        vul_type = vul_name
    return vul_type