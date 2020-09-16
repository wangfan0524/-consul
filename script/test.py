#!/usr/bin/env python
# encoding: utf-8

"""
@version: v1.0
@author: Shijie Qin
@license: Apache Licence
@contact: qsj4work@gmail.com
@site: https://shijieqin.github.io
@software: PyCharm
@file: process_self_repair.py
@time: 2018/7/24 下午4:29
"""

import datetime
import os
import sys
import subprocess
import xml.sax.handler
import configparser
import requests
import socket
import re
# 继承xml.sax.handler.ContentHandler
from xml.sax import handler


class PortHandler(xml.sax.handler.ContentHandler):
    count_context = 0

    route_list = []
    route = {}

    def __init__(self):
        self.mapping = {}

    def startElement(self, name, attrs):
        # 获取Connector
        if name == "Connector":
            self.buffer = ""
            self.port = attrs["port"]
            self.protocol = attrs["protocol"]
        # 获取Context
        if name == "Context":
            self.buffer = ""
            self.path = attrs["path"]
            self.docBase = attrs["docBase"]
            route = {"path": attrs["path"]}
            route["docBase"] = attrs["docBase"]
            self.route_list.append(route)

    def endElement(self, name):
        if name == "Connector":
            self.inTitle = False
            self.mapping[self.protocol] = self.port
            # 对于org.apache.coyote.http11.Http11NioProtocol协议特殊化处理
            if self.protocol == 'org.apache.coyote.http11.Http11NioProtocol' or self.protocol == 'org.apache.coyote.http11.Http11Protocol':
                self.mapping['HTTP/1.1'] = self.port
                self.mapping[self.protocol] = self.port
            else:
                self.mapping[self.protocol] = self.port
        if name == "Context":
            self.count_context = self.count_context + 1
            self.inTitle = False
            self.mapping['path'] = self.path
            self.mapping['docBase'] = self.docBase
            # return handler.mapping["path"]


def _now(format="%Y-%m-%d %H:%M:%S"):
    return datetime.datetime.now().strftime(format)


# 可在脚本开始运行时调用，打印当时的时间戳及PID。
def job_start():
    # 判断当前需要重启的Tomcat是否真的宕机了，两次无法访问视为宕机
    print("[%s][PID:%s] job_start" % (_now(), os.getpid()))
    print("脚本名：", sys.argv[0])
    for i in range(1, len(sys.argv)):
        print("参数", i, sys.argv[i])
    if i > 1:
        process_name = sys.argv[2].split(": ")[0]
        if not get_health_status(str(process_name)):
            cmd = '/opt/toolfish/shell/Process-supervisor.sh -a restart {0}'.format(process_name)
            popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            while popen.poll() == None:
                line = popen.stdout.readline()
                sys.stdout.write(line)
                sys.stdout.flush()
            if popen.returncode != 0:
                job_fail("error")
        else:
            job_success(process_name + ':状态正常，无需重启')
    else:
        job_fail("error parameter numbers")


# 可在脚本执行成功的逻辑分支处调用，打印当时的时间戳及PID。
def job_success(msg):
    print("[%s][PID:%s] job_success:[%s]" % (_now(), os.getpid(), msg))
    sys.exit(0)


def get_health_status(process_name):
    parser = xml.sax.make_parser()
    handler = PortHandler()
    parser.setContentHandler(handler)
    # 通过process_name（instance）找到服务
    # 通过supervisord管理进程，所以服务配置统一在/etc/supervisord/下，文件名为process_name.ini
    try:
        serch_tomcat = '/etc/supervisord/' + process_name + '.ini'
        conf = configparser.ConfigParser()
        conf.read(serch_tomcat)
        path = conf.get("program:" + process_name, "directory")
        parser.parse(path + "/conf/server.xml")
        service_host = get_host_ip()
        # 解析handler获取path和port
        if len(handler.route_list) > 1:
            for route in handler.route_list:
                if (len(re.findall(".*u01.*?/webapp.*", route["docBase"], flags=0)) > 0 or
                    len(re.findall(".*u01.*?/itfapp.*", route["docBase"], flags=0)) > 0 or
                    len(re.findall(".*u01.*?/itfweb.*", route["docBase"], flags=0)) > 0):
                    handler.mapping['path'] = route["path"]
                    handler.mapping['docBase'] = route["docBase"]
                    if handler.mapping.__contains__("docBase"):
                        health_check_addr = handler.mapping['docBase'] + '/modules/public/health_check.screen'
                        if os.path.exists(health_check_addr):
                            url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1'] + \
                                  handler.mapping['path'] + '/modules/public/health_check.screen'
                        else:
                            url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1'] + \
                                  handler.mapping['path']
                    else:
                        url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1'] + \
                              handler.mapping['path']
        else:
            if handler.mapping.__contains__("path"):
                # 如果有docbase，则去判断是否存在指定的healthScreen，存在的话需要在健康检查地址后边拼healthScreen
                # 通过docBasre判断是否存在/modules/public/
                if handler.mapping.__contains__("docBase") and (
                        len(re.findall(".*u01.*?/webapp.*", handler.mapping['docBase'], flags=0)) > 0 or
                        len(re.findall(".*u01.*?/itfapp.*", handler.mapping['docBase'], flags=0)) > 0 or
                        len(re.findall(".*u01.*?/itfweb.*", handler.mapping['docBase'], flags=0)) > 0):
                    health_check_addr = handler.mapping['docBase'] + '/modules/public/health_check.screen'
                    if os.path.exists(str(health_check_addr)):
                        url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1'] + \
                              handler.mapping['path'] + '/modules/public/health_check.screen'
                    else:
                        url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1'] + \
                              handler.mapping['path']
                else:
                    url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1'] + \
                          handler.mapping['path']
            else:
                if handler.mapping.__contains__("docBase") and (
                        len(re.findall(".*u01.*?/webapp.*", handler.mapping['docBase'], flags=0)) > 0 or
                        len(re.findall(".*u01.*?/itfapp.*", handler.mapping['docBase'], flags=0)) > 0 or
                        len(re.findall(".*u01.*?/itfweb.*", handler.mapping['docBase'], flags=0)) > 0):
                    health_check_addr = handler.mapping['docBase'] + '/modules/public/health_check.screen'
                    if os.path.exists(str(health_check_addr)):
                        url = "http://" + service_host + ":" + handler.mapping[
                            'HTTP/1.1'] + '/modules/public/health_check.screen'
                    else:
                        url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1']
                else:
                    url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1']
        handler.route_list = []
        print('健康检查地址是:' + url)
        alive_flag = True
        i = 0;
        while i < 2:
            try:
                res = requests.get(url)
                if str(res.status_code) == '200':
                    return True
                else:
                    return False
            except requests.exceptions.ConnectionError as conerr:
                print(conerr)
                i = i + 1
        if i == 2:
            alive_flag = False
        return alive_flag
    except configparser.NoSectionError as e:
        print(process_name + '.ini文件不存在文件')
        return False
    except ValueError as error:
        print('tomcat路径不存在文件')
        return False


# 获取当前主机IP ,优先取环境变量
def get_host_ip():
    if os.getenv('HOPS_IP_ADDR') is not None:
        ip = os.getenv('HOPS_IP_ADDR')
    else:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
    return ip


# 可在脚本执行失败的逻辑分支处调用，打印当时的时间戳及PID。
def job_fail(msg):
    print("[%s][PID:%s] job_fail:[%s]" % (_now(), os.getpid(), msg))
    sys.exit(1)


if __name__ == '__main__':
    job_start()

    # PortHandler.get_check_path("woer-itfweb-1")
