# -*- coding: utf-8 -*-
import random
import struct
import time

from burp import IBurpExtender, IHttpListener
import socket
from urlparse import urlparse, parse_qs  # Jython 2.7 的 URL 解析模块
from java.util.concurrent import Executors
import threading


class BurpExtender(IBurpExtender, IHttpListener):

    exclude_url = ['bing.com', "googleapis.com", "google.com", 'baidu.com', 'microsoft.com', 'msn.com', 'nelreports.net', 'azure.com', 'bdstatic.com']
    exclude_suffix = ['js', 'css', 'jpeg', 'gif', 'jpg', 'png', 'pdf', 'rar', 'zip', 'docx', 'doc', 'svg', 'jpeg', 'ico', 'woff', 'woff2', 'ttf', 'otf']
    # 可以自行修改IP与端口配置
    host = "127.0.0.1"
    port = 16166

    def __init__(self):
        self.current_iter = 0
        self.socket_count = 5
        self.thread_count = 10
        self.socket_list = []   # socket池子
        self.socket_list_lock = threading.Lock()
        self.socket_lock_list = [threading.Lock() for i in range(5)]

    def init_socket_pool(self):
        for i in range(self.socket_count):
            # 创建初始的socket池
            self.socket_list.append(self.create_socket())

    def create_socket(self):
        host = BurpExtender.host
        port = BurpExtender.port
        try:
            socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_.connect((host, port))
        except Exception as e:
            self._callbacks.printError("create_socket fail: " + str(e))
            exit(-1)
        return socket_

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        callbacks.setExtensionName("HTTP Request Mirror")
        callbacks.registerHttpListener(self)
        self.executor = Executors.newFixedThreadPool(self.thread_count)  # 3 个线程的池
        self.init_socket_pool()     # 创建socket池
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            javaBytes = messageInfo.getRequest()  # 获取 Java byte 数组
            # 获取请求数据（byte数组）
            requestBytes = bytearray(javaBytes)
            # 打印出请求的url
            helper = self._callbacks.getHelpers()
            analyzedRequest = helper.analyzeRequest(messageInfo)
            url = analyzedRequest.getUrl().toString()
            # self._callbacks.printOutput((url))
            # self._callbacks.printOutput(str(type(url)))
            # self._callbacks.printOutput((u"请求Request URL: " + url))
            # self._callbacks.printOutput((u"Request URL: " + url))

            p_url = url.encode('utf-8')
            # 使用 urlparse 解析 URL
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            path = parsed_url.path
            # 目标url、资源不进行转发
            for ex_url in BurpExtender.exclude_url:
                if ex_url in hostname:
                    # self._callbacks.printOutput("ex_url:" + ex_url)
                    return
            for ex_suffix in BurpExtender.exclude_suffix:
                if ex_suffix in path:
                    # self._callbacks.printOutput("ex_suffix:"+ex_suffix)
                    return
            # 将请求数据发送到本地 Python 服务
            # self.sendToPythonListener(requestBytes)
            self.executor.submit(lambda: self.sendToPythonListener(requestBytes))  # 提交任务

    def get_socket(self):
        self.socket_list_lock.acquire()
        # 轮训的方式获取socket
        idx = self.current_iter
        self.current_iter = (self.current_iter+1) % self.socket_count
        self.socket_list_lock.release()
        return self.socket_list[idx], idx

    def handle_err_socket(self, socket_, idx):
        try:
            socket_.close()
        except Exception as e:
            self._callbacks.printError("data len:" + str(e))
        self.socket_list_lock.acquire()
        self.socket_list[idx] = self.create_socket()
        self.socket_list_lock.release()


    def sendToPythonListener(self, data):
        # 获取socket
        socket_, idx = self.get_socket()
        self.socket_lock_list[idx].acquire()

        try:
            self._callbacks.printOutput("idx-{} handle this data".format(idx))
            # 发送header
            socket_.sendall(struct.pack('!BI', 1, len(data)))
            # 发送数据
            socket_.sendall(data)
        except Exception as e:
            self._callbacks.printError(("send data fail: " + str(e)))
            self.handle_err_socket(socket_, idx)
            self.socket_lock_list[idx].release()    # 处理完异常在释放锁
            return
        self.socket_lock_list[idx].release()

