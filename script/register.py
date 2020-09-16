#!/usr/bin/env python
# -*- coding: utf-8 -*-
# !/usr/bin/python
import consul
import psutil
import socket
import os
import re
import json
import logging
import xml.sax.handler
import requests
import platform
import sys

reload(sys)
# python默认为ascii编码
sys.setdefaultencoding('utf8')
print(platform.python_version())


# 继承xml.sax.handler.ContentHandler
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
            return handler.mapping["path"]


class ConsulCenter(object):
    global ip;
    ip = None;

    global balck_box_addr
    balck_box_addr = sys.argv[1]
    balck_box_addr = json.loads(balck_box_addr)

    global consul_addr
    consul_addr = sys.argv[2]
    consul_addr = json.loads(consul_addr)
    global env
    env = sys.argv[3]

    global job_code
    job_code = sys.argv[4]
    global list1
    list1 = ['memcached_exporter', 'mysqld_exporter', 'node_exporter', 'statsd_exporter', 'haproxy_exporter',
             'graphite_exporter', 'consul_exporter', 'blackbox_exporter', 'jmx_exporter', 'oracledb_exporter', 'java']

    global category_list
    category_list = {'blackbox_exporter': 'PROBE/HTTP', 'jmx_exporter': 'WEB/TOMCAT',
                     'oracledb_exporter': 'RDBMS/ORACLE', 'mysqld_exporter': 'RDBMS/MYSQL', 'node_exporter': 'OS/LINUX'}

    global search_tomcat_command
    search_tomcat_command = "ps -ef | grep tomcat | grep Dcatalina | grep -v grep | awk -F '-Dcatalina.base=' '{print $2}' | awk -F ' ' '{print $1}'"

    global host_name
    host_name = socket.gethostname()

    def __init__(this, host, port):
        this._consul = consul.Consul(host, port)

    def get_host_ip(this):
        if os.getenv('HOPS_IP_ADDR') is not None:
            ip = os.getenv('HOPS_IP_ADDR')
        else:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
                # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # return socket.inet_ntoa(fcntl.ioctl(
                #     s.fileno(),
                #     0x8915,
                #     struct.pack('256s', ifname[:15]))[20:24])
            finally:
                s.close()
        return ip

    @staticmethod
    def console_out():
        path = '/tmp/consulelogs/'
        if not (os.path.exists(path)):
            os.mkdir(path)
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                            datefmt='%a, %d %b %Y %H:%M:%S',
                            filename=path + '/register.log',
                            filemode='w')  # 写入模式“w”或“a”
        console = logging.StreamHandler()  # 定义console handler
        console.setLevel(logging.INFO)  # 定义该handler级别
        formatter = logging.Formatter('%(asctime)s  %(filename)s : %(levelname)s  %(message)s')  # 定义该handler格式
        console.setFormatter(formatter)
        logging.getLogger().addHandler(console)  # 实例化添加handler
        logging.info("log初始化成功")

    def RegisterService(this, name, host, port, tags=None, instance1=None, agentIp=None, agentCode=None, sourceIp=None):
        info = this.generateRegisterInfo(name, host, port, tags, instance1, agentIp, agentCode, sourceIp)
        put_string = json.dumps(info)
        # 可能由于网络波动出现注册失败，失败的话重试10次
        i = 0
        while i < 10:
            try:
                # 设置read和连接超时时间
                host = consul_addr['host']
                port = str(consul_addr['port'])
                addr = host + ':' + str(port)
                res = requests.put("http://" + addr + "/v1/agent/service/register", data=put_string, timeout=(5, 5))
                return
            except:
                logging.error('网络异常：' + host + ':' + str(port))
                i = i + 1

        # put_string="'"+put_string+"'"
        # cmd ='curl -X PUT -d '+put_string+' http://10.2.210.2:8500/v1/agent/service/register'
        # res = os.popen(cmd)

    def generateRegisterInfo(this, name, host, port, tags=None, instance1=None, agentIp=None, agentCode=None,
                             sourceIp=None):

        # 基于已有数据构造json结构，采用http客户端的形式发送请求
        Meta = {"agentIp": agentIp}
        if len(instance1) > 0:
            Meta["instance"] = instance1
        if len(agentCode) > 0:
            Meta["agentCode"] = agentCode
            Meta["categoryCode"] = category_list[str(agentCode)]
        if len(sourceIp) > 0:
            Meta["sourceIp"] = sourceIp
        if len(env) > 0:
            Meta["envCode"] = env
        if "blackbox_exporter" in name:
            if len(job_code) > 0:
                Meta["jobCode"] = job_code
        if len(host_name) > 0:
            Meta["hostName"] = host_name

        Meta["tenantId"] = "0"

        info = {"id": name}
        info["name"] = name
        info["address"] = host
        info["port"] = port
        tags = tags
        if env not in tags:
            tags.append(env)
        info["tags"] = tags
        info["Meta"] = Meta
        checks = []
        check = {"tcp": host + ":" + str(port)}
        check["interval"] = "5s"
        check["timeout"] = "30s"
        check["DeregisterCriticalServiceAfter"] = "30s"
        checks.append(check)
        info["checks"] = checks
        return info

    def getTags(this, name, host, port, tags=None):
        tags = tags or []
        this._consul.agent.service.register(name, name, host, port, tags,
                                            check=consul.Check().tcp(host, port, "5s", "30s", "30s"))

    def PutValue(this, key, value):
        this._consul.kv.put(key, value)

    @staticmethod
    def GetService():
        res = None
        try:
            host = consul_addr['host']
            port = str(consul_addr['port'])
            addr = host + ':' + str(port)
            payload = {'dc': 'dc1'}
            name = 'blackbox_exporter' + "_" + env
            res = requests.get("http://" + addr + "/v1/health/service/" + name, params=payload)

        except Exception as err:
            logging.error('普通类型exporter注册异常', err);
        if res == None:
            return None
        state = json.loads(res.text)
        if len(state) == 0:
            return None
        else:
            return state[0]["Service"]["Tags"]

    def GetInstance(this, tomcatPath):
        try:
            cat_yaml_commond = "cat " + tomcatPath + "/info.yaml | grep 'NAME' | awk '{print $2}'"
            cmd = os.popen(cat_yaml_commond)
            # 用readlines方法读取后才是文本对象
            info = cmd.readlines()
            # 将读取的信息中的多个空格替换成一个空格，然后分组
            list1 = str(info).replace('\\n', '').replace("['", '').replace("']", '')
            return list1
        except BaseException as err:
            logging.error(tomcatPath + "下不存在info.yaml文件或tomcat已被禁用，请联系管理员处理")
            return None


if __name__ == '__main__':

    ConsulCenter.console_out()
    # consul主机信息
    consul_host = consul_addr['host']
    # consul端口
    consul_port = str(consul_addr['port'])
    # consul客户端实力
    consul_client = ConsulCenter(consul_host, consul_port)
    logging.info('consul连接成功')
    # 获取当前主机的IP
    service_host = consul_client.get_host_ip()
    logging.info('当前主机IP获取成功：' + service_host)
    # 获取所有进程信息
    pids = psutil.pids()
    for pid in pids:
        if psutil.pid_exists(pid):
            # psutil.pids()获取的时候进程存在，可能获取具体信息的时候进程已经结束，所以进入循环后先判断进程的存在性
            p = psutil.Process(pid)
            # 根据pid查端口
            if p.name() in list1:
                if (p.name() != "java"):
                    # 构造linux指令
                    cmd = 'netstat -nap | grep ' + ' ' + str(p.pid)
                    # 进程名称
                    name = p.name()
                    # 执行命令，获取文件
                    a = os.popen(cmd)
                    # 用readlines方法读取后才是文本对象
                    text = a.readlines()
                    # 遍历数组
                    for obj in text:
                        try:
                            temp = obj.split(':')
                            # 判断是否是Listen接口
                            s = ''.join(temp)
                            if "LISTEN" in s:
                                service_port = int(temp[3])
                                if p.name() == "blackbox_exporter":
                                    if len(balck_box_addr) == 0:
                                        # 获取tomcat
                                        tomcats = os.popen(search_tomcat_command)
                                        # 按行读取
                                        tomcats = tomcats.readlines()
                                        tags = []
                                        # 构造xml解析器
                                        parser = xml.sax.make_parser()
                                        handler = PortHandler()

                                        parser.setContentHandler(handler)
                                        for tomcat in tomcats:
                                            # 获取配置文件的真实路径
                                            tomcatPath = tomcat.replace('\n', '')
                                            # 读取yaml文件
                                            instance = consul_client.GetInstance(tomcatPath)

                                            logging.info('tomcat:'+str(tomcat) + '对应的instance-->' + str(instance))
                                            if instance is None or len(str(instance)) == 0:
                                                continue
                                            realConfPath = tomcatPath + '/conf/server.xml'
                                            if os.path.isfile(realConfPath):
                                                parser.parse(realConfPath)
                                                if handler.mapping.__contains__("path"):
                                                    url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1'] + \
                                                          handler.mapping['path']
                                                    sourceIp = service_host
                                                    dic = {"endpoint": url}
                                                    dic["envCode"] = env
                                                    dic["hostName"] = host_name
                                                    dic["instance"] = instance
                                                    dic["sourceIp"] = sourceIp
                                                    if handler.mapping['path'] == '/':
                                                        tags.append(handler.mapping['HTTP/1.1'])
                                                        consul_client.PutValue(
                                                            service_host.replace('.', '_') + '/' + str(
                                                                handler.mapping['HTTP/1.1']),
                                                            json.dumps(dic))
                                                    else:
                                                        tags.append(
                                                            handler.mapping['HTTP/1.1'] + handler.mapping['path'])
                                                        consul_client.PutValue(
                                                            service_host.replace('.', '_') + '/' + handler.mapping[
                                                                'HTTP/1.1'] + handler.mapping['path'],
                                                            json.dumps(dic))
                                                else:
                                                    url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1']
                                                    sourceIp = service_host
                                                    dic = {"endpoint": url}
                                                    dic["envCode"] = env
                                                    dic["hostName"] = host_name
                                                    dic["instance"] = instance
                                                    dic["sourceIp"] = sourceIp
                                                    tags.append(service_host.replace('.', '_') + '/' + handler.mapping[
                                                        'HTTP/1.1'])
                                                    consul_client.PutValue(handler.mapping['HTTP/1.1'],
                                                                           json.dumps(dic))
                                        res = ConsulCenter.GetService()
                                        agentCode = "blackbox_exporter"
                                        if res != None and len(res) > 0:
                                            inuseTags = res
                                            # 遍历当前的tags，如果当前tags的元素未出现在已经使用的tags中，则进行拼接
                                            for tag in tags:
                                                if tag in inuseTags:
                                                    logging.info(tag)
                                                else:
                                                    inuseTags.append(tag)
                                            agentIp = service_host

                                            consul_client.RegisterService(
                                                name + "_" + service_host.replace('.', '_') + "_" + str(service_port),
                                                service_host, service_port, inuseTags,
                                                "", agentIp, agentCode, "")
                                            logging.info('blockboxexporter注册成功');
                                        else:
                                            agentIp = service_host

                                            consul_client.RegisterService(
                                                name + "_" + service_host.replace('.', '_') + "_" + str(service_port),
                                                service_host, service_port, tags, "",
                                                agentIp, agentCode, "")
                                            logging.info('blockboxexporter注册成功');

                                elif p.name() == "node_exporter":
                                    # 非blackbox类型的tag还是返回agentCode
                                    dic = {"agentCode": name}
                                    xu = json.dumps(dic)
                                    tags = [xu]
                                    instance1 = service_host + ":" + bytes(service_port)
                                    agentIp = service_host
                                    agentCode = name
                                    sourceIp = service_host
                                    consul_client.RegisterService(
                                        name + "_" + service_host.replace('.', '_') + "_" + str(service_port),
                                        service_host, service_port, tags, instance1, agentIp, agentCode, sourceIp)
                                    logging.info(name + '注册成功');
                                else:
                                    # 非blackbox类型的tag还是返回agentCode
                                    dic = {"agentCode": name}
                                    xu = json.dumps(dic)
                                    tags = [xu]
                                    instance1 = service_host + ":" + bytes(service_port)
                                    agentIp = service_host
                                    agentCode = name
                                    sourceIp = service_host
                                    consul_client.RegisterService(
                                        name + "_" + service_host.replace('.', '_') + "_" + str(service_port),
                                        service_host, service_port, tags, instance1, agentIp, agentCode, sourceIp)
                                    logging.info(name + '注册成功');
                                # res = consul_client.GetService(name)
                                break
                        except BaseException as err:
                            logging.error(name + '注册异常');
                        else:
                            continue
                    a.close()
            else:
                continue

    # 针对jmx_exporter
    # cmd = "ps -ef | grep jmx_exporter | awk '{print $1}'"
    cmd = "ps -ef | grep jmx_exporter"
    jmx = os.popen(cmd)
    jmx_exporters = jmx.readlines()
    for jmx_exporter in jmx_exporters:
        try:
            result = re.findall("jmx_.+?\.jar=\d+?:", jmx_exporter, flags=0)
            if len(result) > 0:
                # 将ps -ef | grep命令的返回值进行正则处理，将多个空格替换为一个空格，方便后续获取PID
                result2 = re.sub(' +', ' ', jmx_exporter).split(' ')
                # result1 = re.findall(r"\d+\.?\d*", jmx_exporter, flags=0)
                cmd1 = "ps -ef | grep tomcat | grep " + result2[
                    1] + " | grep -v grep | awk -F '-Dcatalina.base=' '{print $2}' | awk -F ' ' '{print $1}'"
                # 获取tomcat
                tomcats = os.popen(cmd1)
                # 按行读取
                tomcats = tomcats.readlines()
                tags = []
                # 构造xml解析器
                parser = xml.sax.make_parser()
                handler = PortHandler()
                parser.setContentHandler(handler)
                instance = None
                flag = False
                for tomcat in tomcats:
                    # 获取配置文件的真实路径
                    tomcatPath = tomcat.replace('\n', '')
                    # 读取yaml文件
                    instance = consul_client.GetInstance(tomcatPath)
                    logging.info('tomcat'+str(tomcat) + '对应的instance:' + str(instance))
                    if instance is None or len(str(instance)) == 0:
                        flag = True
                if flag:
                    continue
                exporter_str_list = result[0].split('=')
                str_port = exporter_str_list[1]
                pos = str_port.rfind(':')
                str_port = str_port[:pos] + str_port[pos + 1:]
                service_port = int(str_port)
                name = "jmx_exporter"
                dic = {"agentCode": name}
                xu = json.dumps(dic)
                tags = [xu]
                instance1 = instance
                agentIp = service_host
                agentCode = name
                sourceIp = service_host
                consul_client.RegisterService(name + "_" + service_host.replace('.', '_') + "_" + str(service_port),
                                              service_host, service_port, tags, instance1, agentIp, agentCode, sourceIp)
                logging.info(service_host + ":" + str(service_port) + ":" + name + '注册成功');
        except BaseException as err:
            logging.error('jmx_exporter(java-jar类型)', err);
    jmx.close()
    # 针对容器内启动的jmx_exporter
    cmd = "ps -ef | grep jmx_prometheus_javaagent"
    jmx = os.popen(cmd)
    jmx_exporters = jmx.readlines()
    for jmx_exporter in jmx_exporters:
        try:
            result = re.findall("jmx_.+?\.jar=\d+?:", jmx_exporter, flags=0)
            if len(result) > 0:
                result2 = re.sub(' +', ' ', jmx_exporter).split(' ')
                cmd1 = "ps -ef | grep tomcat | grep " + result2[
                    0] + " | grep -v grep | awk -F '-Dcatalina.base=' '{print $2}' | awk -F ' ' '{print $1}'"
                # 获取tomcat
                tomcats = os.popen(cmd1)
                # 按行读取
                tomcats = tomcats.readlines()
                tags = []
                # 构造xml解析器
                parser = xml.sax.make_parser()
                handler = PortHandler()
                parser.setContentHandler(handler)
                instance = None
                flag = False
                for tomcat in tomcats:
                    # 获取配置文件的真实路径
                    tomcatPath = tomcat.replace('\n', '')
                    # 读取yaml文件
                    instance = consul_client.GetInstance(tomcatPath)
                    logging.info('tomcat:'+str(tomcat) + '对应的instance-->' + str(instance))
                    if instance is None or len(str(instance)) == 0:
                        flag = True
                if flag:
                    continue
                exporter_str_list = result[0].split('=')
                str_port = exporter_str_list[1]
                pos = str_port.rfind(':')
                str_port = str_port[:pos] + str_port[pos + 1:]
                service_port = int(str_port)
                name = "jmx_exporter"
                dic = {"agentCode": name}
                xu = json.dumps(dic)
                tags = [xu]
                instance1 = instance
                agentIp = service_host
                agentCode = name
                sourceIp = service_host
                consul_client.RegisterService(name + "_" + service_host.replace('.', '_') + "_" + str(service_port),
                                              service_host, service_port, tags, instance1, agentIp, agentCode, sourceIp)
                logging.info(service_host + ":" + str(service_port) + ":" + name + '注册成功');
        except BaseException as err:
            logging.error('jmx_exporter(tomcat容器内启动类型)', err);
    jmx.close()

    # 针对统一配置的blackbox进行处理
    if len(balck_box_addr) > 0:
        name = 'blackbox_exporter'
        # 获取tomcat
        cmd = os.popen(search_tomcat_command)
        # 按行读取
        tomcats = cmd.readlines()
        tags = []
        # 构造xml解析器
        parser = xml.sax.make_parser()
        handler = PortHandler()
        parser.setContentHandler(handler)
        for tomcat in tomcats:
            # 获取配置文件的真实路径
            tomcatPath = tomcat.replace('\n', '')
            # 读取yaml文件
            instance = consul_client.GetInstance(tomcatPath)
            if instance is None or len(str(instance)) == 0:
                continue
            logging.info('tomcat:'+str(tomcat) + '对应的instance-->' + str(instance))
            realConfPath = tomcatPath + '/conf/server.xml'
            if os.path.isfile(realConfPath):
                parser.parse(realConfPath)
                # 如果配置了两个路径，则去匹配docBase包含/u01/xxx/webapp/webRoot，否则就取本身的
                if len(handler.route_list) > 1:
                    for route in handler.route_list:
                        if len(re.findall(".*u01.*?/webapp.*", route["docBase"], flags=0)) > 0 or len(
                                re.findall(".*u01.*?/itfapp.*", route["docBase"], flags=0)) > 0 or len(
                                re.findall(".*u01.*?/itfweb.*", route["docBase"], flags=0)) > 0:
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
                            logging.info("tomcat实例：" + instance + "健康检查地址为->" + url)
                            sourceIp = service_host
                            dic = {"endpoint": url}
                            dic["envCode"] = env
                            dic["hostName"] = host_name
                            dic["instance"] = instance
                            dic["sourceIp"] = sourceIp
                            if handler.mapping['path'] == '/':
                                tags.append(service_host.replace('.', '_') + '/' + handler.mapping['HTTP/1.1'])
                                consul_client.PutValue(
                                    service_host.replace('.', '_') + '/' + str(handler.mapping['HTTP/1.1']),
                                    json.dumps(dic))
                            else:
                                tags.append(
                                    service_host.replace('.', '_') + '/' + handler.mapping['HTTP/1.1'] +
                                    handler.mapping[
                                        'path'])
                                consul_client.PutValue(
                                    service_host.replace('.', '_') + '/' + handler.mapping['HTTP/1.1'] +
                                    handler.mapping[
                                        'path'],
                                    json.dumps(dic))

                else:
                    if handler.mapping.__contains__("path"):
                        # 如果有docbase，则去判断是否存在指定的healthScreen，存在的话需要在健康检查地址后边拼healthScreen
                        # 通过docBasre判断是否存在/modules/public/
                        if handler.mapping.__contains__("docBase") and (
                                len(re.findall(".*u01.*?/webapp.*", handler.mapping['docBase'], flags=0)) > 0 or len(
                            re.findall(".*u01.*?/itfapp.*", handler.mapping['docBase'], flags=0)) > 0 or len(
                            re.findall(".*u01.*?/itfweb.*", handler.mapping['docBase'], flags=0)) > 0):
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
                        logging.info("tomcat实例：" + instance + "健康检查地址为 -->" + url)
                        sourceIp = service_host
                        dic = {"endpoint": url}
                        dic["envCode"] = env
                        dic["hostName"] = host_name
                        dic["instance"] = instance
                        dic["sourceIp"] = sourceIp
                        if handler.mapping['path'] == '/':
                            tags.append(service_host.replace('.', '_') + '/' + handler.mapping['HTTP/1.1'])
                            consul_client.PutValue(
                                service_host.replace('.', '_') + '/' + str(handler.mapping['HTTP/1.1']),
                                json.dumps(dic))
                        else:
                            tags.append(
                                service_host.replace('.', '_') + '/' + handler.mapping['HTTP/1.1'] + handler.mapping[
                                    'path'])
                            consul_client.PutValue(
                                service_host.replace('.', '_') + '/' + handler.mapping['HTTP/1.1'] + handler.mapping[
                                    'path'],
                                json.dumps(dic))
                    else:
                        if handler.mapping.__contains__("docBase") and (
                                len(re.findall(".*u01.*?/webapp.*", handler.mapping['docBase'], flags=0)) > 0 or len(
                            re.findall(".*u01.*?/itfapp.*", handler.mapping['docBase'], flags=0)) > 0 or len(
                            re.findall(".*u01.*?/itfweb.*", handler.mapping['docBase'], flags=0)) > 0):
                            health_check_addr = handler.mapping['docBase'] + '/modules/public/health_check.screen'
                            if os.path.exists(str(health_check_addr)):
                                url = "http://" + service_host + ":" + handler.mapping[
                                    'HTTP/1.1'] + '/modules/public/health_check.screen'
                            else:
                                url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1']
                        else:
                            url = "http://" + service_host + ":" + handler.mapping['HTTP/1.1']
                        logging.info("tomcat实例：" + instance + "健康检查地址为->" + url)
                        sourceIp = service_host
                        dic = {"endpoint": url}
                        dic["envCode"] = env
                        dic["hostName"] = host_name
                        dic["instance"] = instance
                        dic["sourceIp"] = sourceIp
                        tags.append(service_host.replace('.', '_') + '/' + handler.mapping['HTTP/1.1'])
                        consul_client.PutValue(service_host.replace('.', '_') + '/' + handler.mapping['HTTP/1.1'],
                                               json.dumps(dic))
                handler.route_list = []
                logging.info('*************************************************************************************')
        res = ConsulCenter.GetService()
        box_host = balck_box_addr['host']
        box_host = box_host.encode("utf-8")
        box_port = balck_box_addr['port']
        agentCode = "blackbox_exporter"
        if res != None:
            inuseTags = res
            # 遍历当前的tags，如果当前tags的元素未出现在已经使用的tags中，则进行拼接
            for tag in tags:
                if tag not in inuseTags:
                    inuseTags.append(tag)
            agentIp = service_host
            consul_client.RegisterService(name + "_" + env, box_host, box_port, inuseTags, "", agentIp, agentCode, "")
            logging.info('tomcat健康检查注册成功');

        else:
            agentIp = service_host
            consul_client.RegisterService(name + "_" + env, box_host, box_port, tags, "", agentIp, agentCode, "")
            logging.info('tomcat健康检查注册成功');
        cmd.close()