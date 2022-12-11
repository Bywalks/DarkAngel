import sys
import pathlib
import os

from loguru import logger

# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks

# 路径设置，日志保存路径
log_path = "/root/vuln_scan/vulscan/results/log/vulnlog"
#print(log_path)
# 日志配置
# 终端日志输出格式
stdout_fmt = '<cyan>{time:HH:mm:ss,SSS}</cyan> ' \
             '[<level>{level: <5}</level>] ' \
             '<blue>{module}</blue>:<cyan>{line}</cyan> - ' \
             '<level>{message}</level>'
# 日志文件记录格式
logfile_fmt = '<light-green>{time:YYYY-MM-DD HH:mm:ss,SSS}</light-green> ' \
              '[<level>{level: <5}</level>] ' \
              '<blue>{module}</blue>.<blue>{function}</blue>:' \
              '<blue>{line}</blue> - <level>{message}</level>'

logger.remove()
logger.level(name='TRACE', color='<cyan><bold>', icon='✏️')
logger.level(name='DEBUG', color='<blue><bold>', icon='🐞 ')
logger.level(name='INFOR', no=20,  color='<green><bold>', icon='ℹ️')
logger.level(name='QUITE', no=25, color='<green><bold>', icon='🤫 ')
logger.level(name='ALERT', no=30, color='<yellow><bold>', icon='⚠️')
logger.level(name='ERROR', color='<red><bold>', icon='❌️')
logger.level(name='FATAL', no=50, color='<RED><bold>', icon='☠️')

# 如果你想在命令终端静默运行OneForAll，可以将以下一行中的level设置为QUITE
# 命令终端日志级别默认为INFOR
logger.add(sys.stderr, level='INFOR', format=stdout_fmt, enqueue=True)
# 日志文件默认为级别为DEBUG
logger.add(str(log_path)+"_{time}.log", level='DEBUG', format=logfile_fmt, enqueue=True, encoding='utf-8', rotation = '5 MB', retention='7 days')
#logger.log("INFOR","test")

