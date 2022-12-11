# !/usr/bin/env python
# -*-coding:utf-8 -*-
'''
# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks
'''

import os, sys
from configparser import ConfigParser

config = ConfigParser()
base_path = os.path.abspath(os.path.dirname(__file__))
config_path = base_path + os.sep + "config.ini"

if os.path.exists(config_path):
    config.read(config_path)
else:
    print("file path not exists:", config_path)
    exit(-1)

if config.has_section("es"):
    ES_HOSTS = config.get('es', "hosts")
    if ES_HOSTS:
        ES_HOSTS = ES_HOSTS.split(',')
    ES_USER = config.get('es', "auth_user")
    ES_PASSWD = config.get('es', "auth_passwd")

if config.has_section("h1"):
    H1_COOKIE = config.get('h1', "h1_cookie")
    X_Csrf_Token = config.get('h1', "X_Csrf_Token")

if config.has_section("bc"):
    BC_COOKIE = config.get('bc', "bc_cookie")

if config.has_section("fuzz"):
    KEY = config.get('fuzz', "key")

if config.has_section("qyweixin"):
    CORPID = config.get('qyweixin', "corpid")
    CORPSECRET = config.get('qyweixin', "corpsecret")
    TOUSER = config.get('qyweixin', "touser")
    TOPARTY = config.get('qyweixin', "toparty")