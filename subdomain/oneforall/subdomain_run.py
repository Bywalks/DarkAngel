import os
import sys
import json
import pkgutil
import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from subdomain.oneforall.oneforall import OneForAll as OneForAll
from subdomain.UrlProbe import UrlProbe
from vcommon.ESHelper import ESHelper
from vconfig.log import logger
from vconfig.config import *

class SubDomain:
    def __init__(self):
        self.host = ""
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.program_index = "program-assets-1"
        self.domain_index = "domain-assets-1"

    def run(self,host):
        if host.startswith("*."):
            self.host = host.replace('*.', '')
        elif host.startswith("*"):
            self.host = host.replace('*', '')
        OneForAll(self.host).run()

    def pars_dns(self):
        try:
            data_bytes = pkgutil.get_data('subdomain.oneforall', f'results/{self.host}.json')
            #data_bytes = pkgutil.get_data('subdomain.oneforall', f'results/mi.com.json')
        except Exception as error:
            logger.log('DEBUG',f'[-]子域名[{self.host}]扫描-读取结果失败,{error}')
        else:
            data_str = data_bytes.decode('utf-8')
            try:
                dns_dict = json.loads(data_str)
            except Exception as error:
                logger.log('DEBUG',f'[-]子域名[{self.host}]扫描-解析结果失败,{error}')
            else:
                return dns_dict

    def read_domains(self,program = None):
        '''读取域名全list'''
        if program == None:
            dsl = {
                'query': {
                    'match_all': {
                    }
                },
                "_source": ["program", "launched_at", "update_time", "domain", "max_severity", "platform", "offer_bounty"]
            }
            domain_list = self.es_helper.query_domains_by_dsl(self.program_index, dsl)
        else:
            dsl = {
                "query": {
                    "match_phrase": {
                        "program": str(program)
                    }
                },
                "_source": ["program", "launched_at", "update_time", "domain", "max_severity", "platform", "offer_bounty"]
            }
            #dsl = {'query': {'match': {'program': str(program)}}}
            domain_list = self.es_helper.query_domains_by_dsl(self.program_index, dsl)
        return domain_list

    def read_domains_by_launched_at(self, gte=None, lt=None):
        '''根据时间读取域名list time格式 2028-01-01T12:10:30Z '''
        if gte == None:
            gte = "2010-01-01"
        if lt == None:
            lt = "2030-01-01"
        dsl = {
            "query": {
                "range": {
                    "launched_at": {
                        "gte": gte,
                        "lt": lt
                    }
                }
            },
            "_source": ["program", "launched_at", "update_time", "domain", "max_severity", "platform", "offer_bounty"]
        }
        domain_list = self.es_helper.query_domains_by_dsl(self.program_index, dsl)
        return domain_list

    def read_domains_by_domain(self, domain):
        '''根据时间读取域名list time格式 2028-01-01T12:10:30Z '''
        dsl = {
            "query": {
                "bool": {
                        "must":
                            {"match_phrase": {"domain": str(domain)}}
                    }
            },
            "_source": ["program", "launched_at", "update_time", "domain", "max_severity", "platform", "offer_bounty"]
        }
        domain_list = self.es_helper.query_domains_by_dsl(self.program_index, dsl)
        return domain_list

    def WriteDomainAssets(self,subdomain_list,psource):
        subdomain_info = {}
        subdomain = psource['domain']
        subdomain_info['platform'] = psource["platform"]
        subdomain_info['program'] = psource['program']
        subdomain_info['pdomain'] = psource['domain']
        subdomain_info['offer_bounty'] = psource['offer_bounty']
        subdomain_info['launched_at'] = psource['launched_at']
        subdomain_info['update_time'] = datetime.datetime.now()
        if "max_severity" in psource:
            subdomain_info['max_severity'] = psource['max_severity']
        for info in subdomain_list:
            subdomain_info['alive'] = info['alive']
            subdomain_info['url'] = info['url']
            subdomain_info['ip'] = info['ip']
            subdomain_info['subdomain'] = info['subdomain']
            subdomain_info['port'] = info['port']
            subdomain_info['status'] = info['status']
            subdomain_info['reason'] = info['reason']
            subdomain_info['title'] = info['title']
            subdomain_info['banner'] = info['banner']
            subdomain_info['addr'] = info['addr']
            if subdomain_info['url'] != None:
                self.es_helper.insert_one_doc(self.domain_index,subdomain_info)
        logger.log('INFOR',f'[+]子域名[{subdomain}]入库完成')

    def scansubdomainlist(self,parent_domain_list):
        for pdomain in parent_domain_list:
            psource = pdomain["_source"]
            psource_domain = pdomain["_source"]["domain"]
            if psource_domain.startswith('*') and len(psource_domain.split("*")) < 3:  # 子域名扫描
                logger.log('INFOR',"1->"+psource_domain)
                self.run(psource_domain.split("/")[0])
                subdomain_list = self.pars_dns()
                if subdomain_list:
                    self.WriteDomainAssets(subdomain_list,psource)
            elif psource_domain.startswith('http') and len(psource_domain.split("/")) <= 4 and len(psource_domain.split("*")) < 2:
                #指纹识别
                if psource_domain.endswith('/'):
                    logger.log('INFOR',"2->"+psource_domain)
                    urlprobe = UrlProbe(psource_domain)
                    asset = urlprobe.run()
                    if asset:
                        urlprobe.WriteAsset(asset,psource)
            elif len(psource_domain.split("(")) < 2 and len(psource_domain.split("/")) < 2 and len(psource_domain.split("*")) < 2:
                logger.log('INFOR',"3->"+psource_domain)
                urlprobe = UrlProbe(psource_domain)
                asset = urlprobe.run()
                if asset:
                    urlprobe.WriteAsset(asset, psource)

    def scansubdomain(self,pdomain):
        psource = pdomain["_source"]
        psource_domain = pdomain["_source"]["domain"]
        if "download" in pdomain["_source"]["domain"]:
            return
        if psource_domain.startswith('*') and len(psource_domain.split("*")) < 3:  # 子域名扫描
            if len(psource_domain.split(".")) > 3 or len(psource_domain.split(".")) < 3:
                return
            logger.log('INFOR',"1->"+psource_domain)
            self.run(psource_domain.split("/")[0])
            subdomain_list = self.pars_dns()
            if subdomain_list:
                #self.es_helper.delete_all_by_pdomain(pdomain=psource_domain)
                self.WriteDomainAssets(subdomain_list,psource)

        elif (psource_domain.startswith('http') or psource_domain.startswith('https')) and len(psource_domain.split("/")) <= 4 and len(psource_domain.split("*")) < 2:
            #指纹识别
            if psource_domain.endswith('/'):
                logger.log('INFOR',"2->"+psource_domain)
                urlprobe = UrlProbe(psource_domain)
                asset = urlprobe.run()
                if asset:
                    urlprobe.WriteAsset(asset,psource)
            elif len(psource_domain.split("/")) == 3:
                 logger.log('INFOR',"2->" + psource_domain)
                 urlprobe = UrlProbe(psource_domain)
                 asset = urlprobe.run()
                 if asset:
                    urlprobe.WriteAsset(asset,psource)
        elif len(psource_domain.split("(")) < 2 and len(psource_domain.split("/")) < 2 and len(psource_domain.split("*")) < 2:
            logger.log('INFOR',"3->"+psource_domain)
            urlprobe = UrlProbe(psource_domain)
            asset = urlprobe.run()
            if asset:
                urlprobe.WriteAsset(asset, psource)

def main():
    #read domain list from es
    '''
    subdomain = SubDomain()
    parent_domain_list = subdomain.read_domains("xiaomi")
    if not parent_domain_list:
        return
    else:
        #处理domain
        subdomain.scansubdomainlist(parent_domain_list)
    
    subdomain = SubDomain()
    domain_info = {'_index': 'program-assets-1', '_type': '_doc', '_id': '7oPgg30BTSI7tKY0QRem', '_score': 1.0,
                   '_source': {'max_severity': 'critical', 'update_time': '2021-12-04T13:17:31.940524',
                               'launched_at': '2021-12-07T06:16:32.482Z', 'domain': '*.krisp.ai', 'program': 'krisp'}}
    subdomain.scansubdomain(domain_info)
    subdomain.es_helper.remove_duplicate_data_in_domain_program("krisp")
    '''
    '''
    subdomain = SubDomain()
    dsl = {
        "query": {
            "match": {
                "domain": "*.mi.com"
            }
        },
        "_source": ["program", "launched_at", "update_time", "domain", "max_severity"]
    }
    # dsl = {'query': {'match': {'program': str(program)}}}
    domain_list = subdomain.es_helper.query_domains_by_dsl(index="program-assets-1", dsl=dsl)
    for pdomain in domain_list:
        logger.log('INFOR',pdomain)

        psource = pdomain["_source"]
        subdomain_list = subdomain.pars_dns()
        if subdomain_list:
            subdomain.WriteDomainAssets(subdomain_list, psource)
    '''
    pass

if __name__ == '__main__':
    main()