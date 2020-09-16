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


def _now(format="%Y-%m-%d %H:%M:%S"):
    return datetime.datetime.now().strftime(format)

# 可在脚本开始运行时调用，打印当时的时间戳及PID。
def job_start():
    print "[%s][PID:%s] job_start" % (_now(), os.getpid())

    print "脚本名：", sys.argv[0]
    for i in range(1, len(sys.argv)):
        print "参数", i, sys.argv[i]
    if i > 1:
        process_name = sys.argv[2].split(": ")[0]
        cmd = '/opt/toolfish/shell/Process-supervisor.sh -a restart {0}'.format(process_name)
        popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        while popen.poll() == None:
            line = popen.stdout.readline()
            sys.stdout.write(line)
            sys.stdout.flush()
        if popen.returncode != 0:
            job_fail("error")
    else:
        job_fail("error parameter numbers")


# 可在脚本执行成功的逻辑分支处调用，打印当时的时间戳及PID。
def job_success(msg):
    print "[%s][PID:%s] job_success:[%s]" % (_now(), os.getpid(), msg)
    sys.exit(0)


# 可在脚本执行失败的逻辑分支处调用，打印当时的时间戳及PID。
def job_fail(msg):
    print "[%s][PID:%s] job_fail:[%s]" % (_now(), os.getpid(), msg)
    sys.exit(1)


if __name__ == '__main__':
    job_start()
