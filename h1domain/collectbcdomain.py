# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks

import re
import os
import sys
import requests
import json
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vcommon.ESHelper import ESHelper
from vcommon.vuln_manage import VulnManager
from vconfig.config import *
from vconfig.log import logger

class CollectBCDomain(object):
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36',
            'content-type': 'application/json',
            "Cookie": BC_COOKIE
        }
        self.vuln_mng = VulnManager()
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.program_index = "program-assets-1"
        self.black_pdomain = ["*.datasheet","*dex.binance.org","https://devstaging.pcapcloud.com/*","marketplace.atlassian.com","www.instagram.com","www.youtube.com","www.linkedin.com","www.twitter.com","twitter.com","www.facebook.com","*.","http(s)://api.overstock.com","https:","https:","*gbtnta.com","api*.netflix.com","3.0"]
        self.black_program = ['codefortynine','moneytreekkog','mastercard-vdp-ext','stiltsoft','okta','eazybi']

    def searchallprogram(self):
        query = {'query': {'match_all': {}}}
        res = self.es_helper.query_domains_by_dsl(self.program_index,dsl=query)
        program_list = []
        if res:
            for each in res:
                program_list.append(each['_source']['program'])
        if program_list:
            program_list = list(set(program_list))
        return program_list

    def searchallprogramdomain(self):
        query = {'query': {'match_all': {}}}
        res = self.es_helper.query_domains_by_dsl(self.program_index,dsl=query)
        domain_list = []
        if res:
            for each in res:
                domain_list.append(each['_source']['domain'].lower())
        return domain_list

    def collect_new_bc_program_domain(self):
        logger.log('INFOR', "Start collecting bc programs")
        #offset = 0
        page = 1
        i = 0
        progcount = 0
        progtotal = 500
        domain_old_list = self.searchallprogramdomain()
        while (progcount < progtotal):
            if i < 20:
                search_url = "https://bugcrowd.com/programs.json?sort[]=promoted-desc&hidden[]=false&page[]=%d" % (page)
                logger.log('INFOR',search_url)
                i = i + 1
                try:
                    resp = requests.get(search_url, headers=self.headers, timeout=30)
                    data = json.loads(resp.text)
                    progcount += len(data["programs"])
                    logger.log('INFOR', "[+] Collecting... (%d programs)" % (progcount))
                    '''
                            - program
                            - launched_at
                            - update_time
                            base_bounty
                            average_bounty_lower_amount
                            average_bounty_upper_amount
                            resolved_report_count
                            - submission_state
                            domain
                            - platform
                            - offer_bounty
                            max_severity
                    '''
                    for program in data["programs"]:
                        node = {}
                        program_name = str(program["code"])
                        # print(program_name)
                        if program_name not in self.black_program:
                            if "program_url" in program:
                                program["full_url"] = "https://bugcrowd.com%s" % (program["program_url"])
                            node['program'] = program_name
                            node['launched_at'] = datetime.now()
                            node['update_time'] = datetime.now()
                            node['submission_state'] = "open"
                            node['platform'] = "bugcrowd"
                            # scan bounty domain
                            # if program['license_key'] != "bug_bounty":
                            if program['license_key'] != "vdp_pro":
                                node['offer_bounty'] = "yes"
                                if "full_url" in program:
                                    self.collectprogramdomain(node, program["code"], domain_old_list)
                            '''
                            # scan not bounty domain
                            else:
                                node['offer_bounty'] = "no"
                                if "full_url" in program:
                                    self.collectprogramdomain(node, program["code"], domain_old_list)
                            '''
                        # update the total from the cursor
                    progtotal = data["meta"]["totalHits"]
                    logger.log('INFOR', "total: %d" % progtotal)
                    #offset = offset + 1
                    page = page + 1
                except Exception as error:
                    logger.log('DEBUG', f'收集bc program时出现异常 - {error}')
            else:
                message = f"collectbcdomain模块的session已过期，请及时更换。"
                self.vuln_mng.send_message(message=message)
                progcount = 1
                progtotal = 0
        logger.log('INFOR', "[+] DONE! Collectprogram ending......")

    def collectprogramdomain(self, node, program, domain_old_list):
        program_url = "https://bugcrowd.com/%s" % (program)
        # print(program_url)
        try:
            resp = requests.get(url=program_url, headers=self.headers, timeout=10)
            if resp.status_code != 200:
                logger.log('INFOR', "[+] Program %s returned a status code %s, skipping program details..." % (program, resp.status_code))
                return None
            data = resp.text
            if data.find("Compliance required") != -1:
                logger.log('INFOR', "[+] Program %s has a compliance agreement which has not been accepted - skipping" % (program))
            else:
                soup = BeautifulSoup(data, features="lxml")
                tags = soup.find_all("div", attrs={"data-react-class": "ResearcherTargetGroups"})
                if len(tags) != 1:
                    logger.log('INFOR', "ERROR: Expected only one `ResearcherTargetGroups` React data")
                try:
                    resp_groups = requests.get(url=f"{program_url}/target_groups", headers=self.headers, timeout=10)
                    program_data = json.loads(resp_groups.text)
                    for group in program_data["groups"]:
                        if group['in_scope'] == True:
                            # separate JSON call now for each target group stats
                            try:
                                url = "https://bugcrowd.com" + group["targets_url"]
                                resp_group_stats = requests.get(url=url, headers=self.headers, timeout=10)
                                group_data = json.loads(resp_group_stats.text)
                                # accumulate total and unique bug counts if the program discloses
                                for target in group_data["targets"]:
                                    node["domain"] = target["name"].strip().split(" ")[0].lower()
                                    node['hackerone_private'] = "no"
                                    if (target["category"] == "website" or target["category"] == "api") and node['domain'] != None and node['domain'] != "" and node['domain'] not in self.black_pdomain and "." in node['domain'] and "[" not in node['domain']:
                                        if "*" in node['domain']:
                                            if node['domain'].startswith("http://") and "*." in node['domain']:
                                                node['domain'] = self.es_helper.remove_http_or_https(node['domain'])
                                            if node['domain'].startswith("https://") and "*." in node['domain']:
                                                node['domain'] = self.es_helper.remove_http_or_https(node['domain'])
                                            if "/" in node['domain'] and node['domain'].count("/") < 2:
                                                node['domain'] = node['domain'].split("/")[0]
                                            if node['domain'].count("*") < 2:
                                                if node['domain'] not in domain_old_list:
                                                    node['domain'] = node['domain'].lower()
                                                    print(node)
                                                    self.es_helper.insert_one_doc(self.program_index, node)
                                                    logger.log('INFOR', program + "-" + node['domain'])
                                                    logger.log('INFOR', node)
                                        else:
                                            # 判断node['domain'] 不为ip
                                            if not re.findall("^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$", node['domain']):
                                                if node['domain'] not in domain_old_list:
                                                    node['domain'] = node['domain'].lower()
                                                    print(node)
                                                    self.es_helper.insert_one_doc(self.program_index, node)
                                                    logger.log('INFOR', program + "-" + node['domain'])
                                                    logger.log('INFOR', node)
                            except Exception as error:
                                logger.log('DEBUG', f'收集bc domain时出现异常 - {error}')
                except Exception as error:
                    logger.log('DEBUG', f'收集bc domain时出现异常 - {error}')
        except Exception as error:
            logger.log('DEBUG', f'收集bc domain时出现异常 - {error}')

if __name__ == "__main__":
    #b1 = CollectBCDomain()
    #b1.collect_new_bc_program_domain()
    pass