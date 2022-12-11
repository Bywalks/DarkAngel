'''探测端口是否为HTTP服务，在加入到web资产表'''

# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks

import os
import sys
import datetime
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/../../')

import requests
import chardet
from bs4 import BeautifulSoup
import random
import ipaddress
from urllib.parse import urlparse
from vcommon.ESHelper import ESHelper
from vconfig.config import *
from vconfig.log import logger
#from subdomain.oneforall.config.log import logger

requests.packages.urllib3.disable_warnings()

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) '
    'Gecko/20100101 Firefox/68.0',
    'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/68.0']

class UrlProbe:

    def __init__(self, url):
        '''
            url = http/https://xxx.com
            url = xxx.com
        '''
        if url.startswith("http"):
            self.url = urlparse(url).hostname
        else:
            self.url = url
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.index = "domain-assets-1"

    def _gen_random_ip(self):
        """生成随机的点分十进制的IP字符串"""
        while True:
            ip = ipaddress.IPv4Address(random.randint(0, 2 ** 32 - 1))
            if ip.is_global:
                return ip.exploded

    def _gen_fake_header(self):
        """生成伪造请求头"""
        ua = random.choice(user_agents)
        ip = self._gen_random_ip()
        headers = {
            'Accept': 'text/html,application/xhtml+xml,'
                      'application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'DNT': '1',
            'Referer': 'https://www.google.com/',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': ua,
            'X-Forwarded-For': ip,
            'X-Real-IP': ip
        }
        return headers

    def _check_http(self):
        '''HTTP服务探测'''
        url = f"http://{self.url}"
        headers = self._gen_fake_header()
        try:
            response = requests.get(url, verify=False, timeout=10, headers=headers)
        except requests.exceptions.SSLError:
            url = f"https://{self.url}"
            try:
                response = requests.get(url, timeout=10, verify=False, headers=headers)
            except Exception as e:
                return None
            else:
                return response
        except Exception as e:
            return None
        else:
            return response

    def _get_banner(self, headers):
        server = headers.get('Server')
        Powered = headers.get('X-Powered-By')
        if server or Powered:
            return f'{server},{Powered}'
        else:
            return ''

    def _get_title(self, markup):
        '''获取网页标题'''
        try:
            logger.log('INFOR',"get title")
            soup = BeautifbulSoup(markup, 'lxml')
        except:
            return None
        title = soup.title
        if title:
            return title.text.strip()
        h1 = soup.h1
        if h1:
            return h1.text.strip()
        h2 = soup.h2
        if h2:
            return h2.text.strip()
        h3 = soup.h3
        if h2:
            return h3.text.strip()
        desc = soup.find('meta', attrs={'name': 'description'})
        if desc:
            return desc['content'].strip()
        word = soup.find('meta', attrs={'name': 'keywords'})
        if word:
            return word['content'].strip()
        if len(markup) <= 200:
            return markup.strip()
        text = soup.text
        if len(text) <= 200:
            return text.strip()
        return None

    def run(self):
        logger.log('INFOR',f'[+]URL开始探测:[{self.url}]')
        response = self._check_http()
        if response == None:  # 非HTTP服务
            logger.log('INFOR',f'[-]URL探测:[{self.url}]非HTTP服务')
            return None
        if response.status_code == 200:
            mychar = chardet.detect(response.content)
            bianma = mychar['encoding']  # 自动识别编码
            response.encoding = bianma
            title = self._get_title(markup=response.text)
            banner = self._get_banner(response.headers)
            assets_dict = {}
            assets_dict['title'] = title
            assets_dict['banner'] = banner
            assets_dict['url'] = response.url
            return assets_dict
        else:
            logger.log('INFOR',f'[-]URL探测:[{self.url}]状态码非200')
            return None


    def WriteAsset(self,assets_dict, psource):
        subdomain_info = {}
        subdomain_info['program'] = psource['program']
        subdomain_info['pdomain'] = psource['domain']
        subdomain_info['platform'] = psource['platform']
        subdomain_info['offer_bounty'] = psource['offer_bounty']
        subdomain_info['launched_at'] = psource['launched_at']
        subdomain_info['update_time'] = datetime.datetime.now()
        if "max_severity" in psource:
            subdomain_info['max_severity'] = psource['max_severity']
        subdomain_info['title'] = assets_dict['title']
        subdomain_info['banner'] = assets_dict['banner']
        subdomain_info['url'] = assets_dict['url']
        subdomain_info['alive'] = 1
        subdomain_info['status'] = 200
        subdomain_info['subdomain'] = self.url
        logger.log('INFOR',subdomain_info)
        if subdomain_info['url'] != None:
            self.es_helper.insert_one_doc(self.index,subdomain_info)

