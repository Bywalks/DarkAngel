# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : xray_scan.py
# Time       ：2021/12/01
# version    ：python 3
# Description：

# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks
"""

import os, sys
import datetime
import time
import requests
import threading
import subprocess
from flask import Flask, request
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vcommon.common import cmdprocess
from vcommon.ESHelper import ESHelper
from vcommon.vuln_manage import VulnManager
from vconfig.config import *
from vconfig.log import logger
#from subdomain.oneforall.config.log import logger

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
requests.packages.urllib3.disable_warnings()

app = Flask(__name__)

NUM_SCAN = 1

class XrayScan(object):
    def __init__(self):
        self.xray_path = CUR_DIR + "/tools/xray"
        self.xray_config = CUR_DIR + "/tools/xray_config.yaml"
        self.xray_cmd = f"{self.xray_path} --config {self.xray_config} "
        self.spiderResultDir = CUR_DIR + "/results/spider"
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.scanner_name = "xray_scan"
        self.spider_index = "spider-assets-1"

    def read_spider_list(self, program=None, pdomain=None, subdomain=None):
        '''根据筛选条件读取spider_data全list'''
        if subdomain != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"subdomain": str(subdomain)}}
                        ]
                    }
                },
                "_source": ["url", "method", "headers", "data"]
            }
        elif pdomain != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"pdomain": str(pdomain)}}
                        ]
                    }
                },
                "_source": ["url", "method", "headers", "data"]
            }
        elif program != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"program": str(program)}}
                        ]
                    }
                },
                "_source": ["url", "method", "headers", "data"]
            }
        else:
            dsl = {
                "query": {
                    "match_all": {}
                },
                "_source": ["url", "method", "headers", "data"]
            }
        spider_list = self.es_helper.query_domains_by_dsl(self.spider_index, dsl)
        return spider_list

    '''爬虫数据去重'''
    def remove_duplicate_data(self, list_dict_data):
        copy_list = []
        for list_data in list_dict_data:
            list_data = list_data['_source']
            num = 0
            for cop in copy_list:
                if list_data['url'] == cop['url'] and list_data['method'] == cop['method'] and list_data['data'] == cop['data']:
                    num += 1
            if num == 0:
                copy_list.append(list_data)
        return copy_list

    def dispatch(self,spider_list):
        logger.log('INFO',"[scanning]")
        # 爬虫结果分阶段打入xray，若Xray待扫描数大于2000，则sleep 300s
        for spider_data in spider_list:
            #spider_data = spider_data['_source']
            if NUM_SCAN >= 2000:
                logger.log('INFO','[-]xray当前队列过多，等待300S后继续打入数据进队列')
                time.sleep(300)
            if spider_data['url'][:2] != "ws":
                proxies = {
                    'http': 'http://127.0.0.1:7777',
                    'https': 'http://127.0.0.1:7777',
                }
                urls0 = spider_data['url']
                logger.log('INFO',spider_data['url'])
                headers0 = spider_data['headers']
                method0 = spider_data['method']
                data0 = spider_data['data']
                #这块不仅可以做xray扫描，也可做漏洞fuzz，待完善
                try:
                    if (method0 == 'GET'):
                        a = requests.get(urls0, headers=headers0, proxies=proxies, timeout=30, verify=False)
                    elif (method0 == 'POST'):
                        a = requests.post(urls0, headers=headers0, data=data0, proxies=proxies, timeout=30, verify=False)
                except Exception as error:
                    logger.log('DEBUG',f'{error}')
                    continue
                finally:
                    logger.log('INFO',NUM_SCAN)
        while True:
            if NUM_SCAN !=0:
                time.sleep(10)
            else:
                logger.log('INFO',"dispatch is ok!")
                break

    def delxray(self):
        searchxray_cmd_line = "ps -ef | grep xray | grep -v grep | awk '{print $2}'"
        output, stderr, return_code = cmdprocess(searchxray_cmd_line)
        logger.log('INFO',"output is : " + output)
        logger.log('INFO',len(output))
        if output:
            result = output.splitlines()
            for re in result:
                os.system(f"kill -9 {re}")

    def startxray(self):
        assert os.path.exists(self.xray_path), f"xray file:{self.xray_path} not exists!"
        assert os.path.exists(self.xray_config), f"xray file:{self.xray_config} not exists!"
        # cmd_lines = f"{self.xray_cmd} webscan --listen 127.0.0.1:7777 --json-output {xray_output_json} >> {self.resultDir}/log.txt"
        cmd_lines = f"{self.xray_cmd} webscan --listen 127.0.0.1:7777 --webhook-output http://127.0.0.1:8899/webhook"
        logger.log('INFO',cmd_lines)
        # 开启xray
        os.system(cmd_lines)
        #subprocess.Popen(cmd_lines, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    def startdispatch(self, program=None, pdomain=None, subdomain=None):
        # 输入program和subdomain
        spider_list = None
        if program != None:
            spider_list = self.read_spider_list(program=program)
        if pdomain != None:
            spider_list = self.read_spider_list(pdomain=pdomain)
        if subdomain != None:
            spider_list = self.read_spider_list(subdomain=subdomain)
        if spider_list!=None:
            logger.log('INFO',"start dispatching ....")
            # 去除重复数据
            spider_list = self.remove_duplicate_data(spider_list)
            # 调度爬虫结果，扫完后关闭flask和xray
            self.dispatch(spider_list)

es = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
vuln_manager = VulnManager()
# 开启webhook监听模块
@app.route('/webhook', methods=['POST'])
def xray_webhook():
    try:
        vuln = request.json
    except Exception as error:
        logger.log('DEBUG',f'{error}')
    else:
        if vuln['type'] == "web_vuln":
            data = vuln['data']
            new_doc = {"scan_name": "xray_scan"}
            new_doc['launched_at'] = datetime.datetime.now()
            new_doc['scan_detail'] = data['detail']
            new_doc['vuln_name'] = data['plugin']
            if data['target']['url']:
                new_doc['website'] = urlparse(data['target']['url']).netloc
            logger.log('INFO',f"Xray新漏洞：[{new_doc['vuln_name']}]-{data['target']}")
            # 添加vul_type和vul_score后打入ES
            vuln_manager.add_vuln_type(new_doc)
            vuln_manager.add_vuln_score(new_doc)
            logger.log('INFO',new_doc)
            vuln_manager.generate_report(new_doc)
            vuln_manager.es_helper.insert_one_doc(index="vuln-assets-1",asset_info=new_doc)
            logger.log('INFO',"find vuln and insert success!")
        else:
            if vuln['type'] == "web_statistic":
                num_found_urls = vuln['data']['num_found_urls']
                num_scanned_urls = vuln['data']['num_scanned_urls']
                pending = int(num_found_urls) - int(num_scanned_urls)
                global NUM_SCAN
                NUM_SCAN = pending
                logger.log('INFO',f'Xray queue [{NUM_SCAN}]')
    finally:
        return "ok"

def start_webhook():
    app.run(port=8899)
