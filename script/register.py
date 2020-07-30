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
# from urllib import request
import requests


# 继承xml.sax.handler.ContentHandler
class PortHandler(xml.sax.handler.ContentHandler):
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

    def endElement(self, name):
        if name == "Connector":
            self.inTitle = False
            self.mapping[self.protocol] = self.port
            # 对于org.apache.coyote.http11.Http11NioProtocol协议特殊化处理
            if self.protocol == 'org.apache.coyote.http11.Http11NioProtocol':
                self.mapping['HTTP/1.1'] = self.port
                self.mapping[self.protocol] = self.port
            else:
                self.mapping[self.protocol] = self.port
        if name == "Context":
            self.inTitle = False
            self.mapping['path'] = self.path
            return handler.mapping["path"]


class ConsulCenter(object):
    global ip;
    ip = None;
    global list1
    list1 = ['memcached_exporter', 'mysqld_exporter', 'node_exporter', 'statsd_exporter', 'haproxy_exporter',
             'graphite_exporter', 'consul_exporter', 'blackbox_exporter', 'jmx_exporter', 'oracledb_exporter', 'java']

    global search_tomcat_command
    search_tomcat_command = "ps -ef | grep tomcat | grep Dcatalina | grep -v grep | awk -F '-Dcatalina.base=' '{print $2}' | awk -F ' ' '{print $1}'"

    def __init__(this, host, port):
        this._consul = consul.Consul(host, port)

    def get_host_ip(this):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
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
        res = requests.put("http://10.8.0.98:8500/v1/catalog/register", data=json.dumps(info))

    def generateRegisterInfo(this, name, host, port, tags=None, instance1=None, agentIp="123", agentCode=None,
                             sourceIp=None):
        # 基于已有数据构造json结构，采用http客户端的形式发送请求
        NodeMeta = {"agentIp": agentIp}
        if len(instance1) > 0:
            NodeMeta["instance"] = instance1
        if len(agentCode) > 0:
            NodeMeta["agentCode"] = agentCode
        if len(sourceIp) > 0:
            NodeMeta["sourceIp"] = sourceIp
        Service = {"ID": name}
        Service["Service"] = name
        Service["Port"] = port
        Service["Tags"] = tags
        info = {"Node": name}
        info["Address"] = host
        info["NodeMeta"] = NodeMeta
        info["Service"] = Service
        Checks = []
        check = {"Name": name}
        check["status"] = "passing"
        Definition = {"http": "https://www.google.com"}
        Definition["interval"] = "30s"
        check["Definition"] = Definition
        Checks.append(check)
        info["Checks"] = Checks
        return info

    def getTags(this, name, host, port, tags=None):
        tags = tags or []
        this._consul.agent.service.register(name, name, host, port, tags,
                                            check=consul.Check().tcp(host, port, "5s", "30s", "30s"))

    def PutValue(this, key, value):
        this._consul.kv.put(key, value)

    def GetService(this, name):
        services = this._consul.agent.services()
        service = services.get(name)
        if not service:
            return None, None
        addr = "{0}:{1}".format(service['Address'], service['Port'])
        return service, addr

    def GetInstance(this, tomcatPath):
        # 将路径按照/分组
        pathList = tomcatPath.split("/")
        firstPath = str(pathList[-1])
        secoundPath = pathList[-2]
        thirdPath = pathList[-3]
        instance = thirdPath + '-' + secoundPath + '-' + firstPath[0:firstPath.index('#')]
        return instance


if __name__ == '__main__':
    host_name = socket.gethostname()
    ConsulCenter.console_out()
    # consul主机信息
    consul_host = "10.8.0.98"
    # consul端口
    consul_port = "8500"
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
                                        instance = consul_client.GetInstance(tomcatPath)
                                        realConfPath = tomcatPath + '/conf/server.xml'
                                        if os.path.isfile(realConfPath):
                                            parser.parse(realConfPath)
                                            if handler.mapping.__contains__("path"):
                                                url = "https://" + service_host + ":" + handler.mapping['HTTP/1.1'] + \
                                                      handler.mapping['path']
                                                sourceIp = service_host
                                                dic = {"endpoint": url}
                                                dic["__param_target"] = url
                                                dic["hostName"] = host_name
                                                dic["instance"] = instance
                                                dic["sourceIp"] = sourceIp
                                                if handler.mapping['path'] == '/':
                                                    tags.append(handler.mapping['HTTP/1.1'])
                                                    consul_client.PutValue(str(handler.mapping['HTTP/1.1']),
                                                                           json.dumps(dic))
                                                else:
                                                    tags.append(handler.mapping['HTTP/1.1'] + handler.mapping['path'])
                                                    consul_client.PutValue(
                                                        handler.mapping['HTTP/1.1'] + handler.mapping['path'],
                                                        json.dumps(dic))
                                            else:
                                                url = "https://" + service_host + ":" + handler.mapping['HTTP/1.1']
                                                sourceIp = service_host
                                                dic = {"endpoint": url}
                                                dic["__param_target"] = url
                                                dic["hostName"] = host_name
                                                dic["instance"] = instance
                                                dic["sourceIp"] = sourceIp
                                                tags.append(handler.mapping['HTTP/1.1'])
                                                consul_client.PutValue(handler.mapping['HTTP/1.1'],
                                                                       json.dumps(dic))
                                    if len(tags) == 0:
                                        tags.append("NoneTomcat")
                                    res = consul_client.GetService(name)
                                    if res[0] != None:
                                        tagsdict = res[0]
                                        inuseTags = tagsdict.get('Tags')
                                        # 遍历当前的tags，如果当前tags的元素未出现在已经使用的tags中，则进行拼接
                                        for tag in tags:
                                            if tag in inuseTags:
                                                logging.info(tag)
                                            else:
                                                inuseTags.append(tag)
                                        agentIp = service_host
                                        logging.info('blockboxexporter注册1');
                                        consul_client.RegisterService(
                                            name, service_host, service_port, inuseTags,"",agentIp,"","")
                                        logging.info('blockboxexporter注册成功');
                                    else:
                                        agentIp = service_host
                                        logging.info('blockboxexporter注册2');
                                        consul_client.RegisterService(name, service_host, service_port, tags,"",agentIp,"","")
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
                                    logging.info('node_exporter注册成功');
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
                                    logging.info('普通类型exporter注册成功');
                                # res = consul_client.GetService(name)
                                break
                        except BaseException as err:
                            logging.error('普通类型exporter注册异常', err);
                        else:
                            continue
            else:
                continue

    # 针对jmx_exporter
    cmd = "ps -ef | grep jmx_exporter"
    jmx = os.popen(cmd)
    jmx_exporters = jmx.readlines()
    for jmx_exporter in jmx_exporters:
        try:
            result = re.findall("jmx_.+?\.jar=\d+?:", jmx_exporter, flags=0)
            if len(result) > 0:

                result1= re.findall(r"\d+\.?\d*", jmx_exporter, flags=0)
                cmd1 = "ps -ef | grep tomcat | grep "+ result1[0]+" | grep -v grep | awk -F '-Dcatalina.base=' '{print $2}' | awk -F ' ' '{print $1}'"
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
                for tomcat in tomcats:
                    # 获取配置文件的真实路径
                    tomcatPath = tomcat.replace('\n', '')
                    instance = consul_client.GetInstance(tomcatPath)
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
    # 针对容器内启动的jmx_exporter
    cmd = "ps -ef | grep jmx_prometheus_javaagent"
    jmx = os.popen(cmd)
    jmx_exporters = jmx.readlines()
    for jmx_exporter in jmx_exporters:
        try:
            result = re.findall("jmx_.+?\.jar=\d+?:", jmx_exporter, flags=0)
            if len(result) > 0:
                result1 = re.findall(r"\d+\.?\d*", jmx_exporter, flags=0)

                cmd1 = "ps -ef | grep tomcat | grep "+ result1[0]+" | grep -v grep | awk -F '-Dcatalina.base=' '{print $2}' | awk -F ' ' '{print $1}'"
                # 获取tomcat
                tomcats = os.popen(cmd1)
                # 按行读取
                tomcats = tomcats.readlines()
                tags = []
                # 构造xml解析器
                parser = xml.sax.make_parser()
                handler = PortHandler()
                parser.setContentHandler(handler)
                instance=None
                for tomcat in tomcats:
                    # 获取配置文件的真实路径
                    tomcatPath = tomcat.replace('\n', '')
                    instance = consul_client.GetInstance(tomcatPath)
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
