import copy
import os
import threading
from email.parser import BytesParser
from urllib.parse import urlparse, parse_qs
import hashlib
from concurrent.futures import ThreadPoolExecutor
import requests
import yaml
from pathlib import Path
import time


class PrivilegeEscalation:
    config = None
    hash_set = set()
    md5 = hashlib.md5()
    executor = ThreadPoolExecutor(max_workers=5)
    config_path = './config.yaml'
    result_path = "./result.txt"
    write_lock = threading.Lock()

    @staticmethod
    def safe_create_directory(path):
        try:
            path_obj = Path(path)
            path_obj.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"创建目录时出错: {e}")
            return False
        return True
    @staticmethod
    def set_config_path(path):
        if os.path.exists(path) and os.path.isfile(path):
            PrivilegeEscalation.config_path = path
        else:
            print("config_path error")
            exit(-1)

    @staticmethod
    def set_save_path(path):
        if not PrivilegeEscalation.safe_create_directory(path):
            print("save pth 创建失败")
            exit(-1)
        PrivilegeEscalation.result_path = path+str(int(time.time()))+".txt"

    @staticmethod
    def hash_url(path):
        md5 = hashlib.md5()
        md5.update(path.encode('utf-8'))
        hash_value = md5.hexdigest()
        if hash_value not in PrivilegeEscalation.hash_set:
            PrivilegeEscalation.hash_set.add(hash_value)
            return True     # 没访问过
        else:
            return False    # 访问过

    @staticmethod
    def send_request(method, url, query_params, headers_dict, cookies, body):
        # 获得越权参数
        q, h, c = PrivilegeEscalation.get_payload(query_params, headers_dict, "PriEsc")
        # 获得未授权参数
        q_, h_, c_ = PrivilegeEscalation.get_payload(query_params, headers_dict, "UnAuth")
        # 进行请求
        try:
            res1 = requests.request(
                method=method, url=url, data=body, cookies=cookies, params=query_params,
                headers=headers_dict, allow_redirects=False
            )
            res2 = requests.request(
                method=method, url=url, data=body, cookies=c, params=q,
                headers=h, allow_redirects=False
            )
            res3 = requests.request(
                method=method, url=url, data=body, cookies=c_, params=q_,
                headers=h_, allow_redirects=False
            )
        except Exception as e:
            print("3个请求发生错误：", e)
            return False
        return [res1, res2, res3]

    @staticmethod
    def check_exist(res_list):
        # 可以增加额外判定，这里只做两个，status_code 和 length
        result = {}
        key_li = ["pri_esc", "un_auth"]
        nol = res_list[0]
        pri = res_list[1]
        una = res_list[2]
        for ob, key in zip([pri, una], key_li):
            if ob.status_code != nol.status_code and len(ob.content) != len(nol.content):
                pass
            elif ob.status_code == nol.status_code and len(ob.content) == len(nol.content):
                result[key] = "high"
            elif ob.status_code != nol.status_code and len(ob.content) == len(nol.content):
                result[key] = "median"
            else:
                pass
        if not result:
            return None
        return result

    @staticmethod
    def save_data(res_dic):
        print(res_dic)  # 打印log
        # 用锁保证安全
        PrivilegeEscalation.write_lock.acquire()
        with open(PrivilegeEscalation.result_path, 'a') as f:
            f.write(str(res_dic) + '\n')
        PrivilegeEscalation.write_lock.release()

    @staticmethod
    def run(raw_request):
        method, url, query_params, headers_dict, cookies, body = PrivilegeEscalation.parse_http(raw_request)

        # 1、hash检测，
        if not PrivilegeEscalation.hash_url(method+url):
            return
        # 2、进行越权测试
        res_list = PrivilegeEscalation.send_request(method, url, query_params, headers_dict, cookies, body)
        if not res_list:
            return
        # 3、验证是否存在漏洞
        res_dic = PrivilegeEscalation.check_exist(res_list)
        if not res_dic:
            return
        # 4、进行结果保存
        res_dic['url'] = url
        res_dic['method'] = method
        res_dic['query'] = str(query_params)
        # 线程处理
        PrivilegeEscalation.executor.submit(PrivilegeEscalation.save_data, res_dic)

    @staticmethod
    def parse_http(raw_request):
        # 分割请求头和请求体
        header_section, body = raw_request.split(b'\r\n\r\n', 1)

        # 解析起始行
        lines = header_section.split(b'\r\n')
        request_line = lines[0].decode()
        method, url, http_version = request_line.split(' ')

        # 解析请求头
        headers = BytesParser().parsebytes(b'\r\n'.join(lines[1:]))
        headers_dict = dict(headers)

        scheme = "http"
        host = headers_dict.get("Host", "")  # wenti
        if ":443" in host:
            scheme = "https"
        elif host.endswith(":80"):
            scheme = "http"
        elif headers_dict.get("Referer", "").startswith("https://") or headers_dict.get("Origin", "").startswith(
                "https://"):
            scheme = "https"
        elif http_version == "HTTP/2":
            scheme = "https"  # HTTP/2 大多数情况是 HTTPS，但需配合 Host 确认

        # 补全url
        if not url.startswith("http"):
            url = f"{scheme}://{host}{url}"

        # 解析 URL
        parsed_url = urlparse(url)
        url = url.split('?', 1)[0]
        query_params = parse_qs(parsed_url.query)

        # 解析 Cookies
        cookies = {}
        if 'Cookie' in headers_dict:
            for c in headers_dict.pop('Cookie').split('; '):
                k, v = c.split('=', maxsplit=1)
                cookies[k] = v
        # print(url)
        # print(query_params)
        # response = requests.post(url, headers=headers_dict, cookies=cookies, data=body, params=query_params)
        return method, url, query_params, headers_dict, cookies, body

    @staticmethod
    def get_config():
        if not PrivilegeEscalation.config:
            with open(PrivilegeEscalation.config_path, "r") as f:
                PrivilegeEscalation.config = yaml.safe_load(f)
        return PrivilegeEscalation.config

    @staticmethod
    def get_modify_query(query_params, modi_type):
        cf = PrivilegeEscalation.get_config()
        q_pri = copy.deepcopy(query_params)
        if modi_type not in cf:
            return q_pri
        qp_list = cf[modi_type]
        if not qp_list:
            return q_pri
        for item in qp_list:
            if item['cover'] or item['segment'] not in q_pri:
                q_pri[item['segment']] = [item['value']]
            else:
                q_pri[item['segment']].append(item['value'])
        return q_pri

    @staticmethod
    def get_modify_headers(headers, modi_type):
        cf = PrivilegeEscalation.get_config()
        h_pri = copy.deepcopy(headers)
        if modi_type not in cf:
            return h_pri
        hd_list = cf[modi_type]
        if not hd_list:
            return h_pri
        for item in hd_list:
            if item['cover'] or item['segment'] not in h_pri:
                h_pri[item['segment']] = item['value']
            else:
                h_pri[item['segment']] = h_pri[item['segment']] + ", " + str(item['value'])
        return h_pri

    @staticmethod
    def get_modify_cookies(modi_type):
        cf = PrivilegeEscalation.get_config()
        cookies = {}
        if modi_type not in cf:
            return cookies
        cookies_str = cf[modi_type]
        if not cookies_str:
            return cookies
        for c in cookies_str.split('; '):
            k, v = c.split('=', maxsplit=1)
            cookies[k] = v
        return cookies

    @staticmethod
    def get_payload(query_params, headers_dict, mode_type):  # mode_type= PriEsc\UnAuth
        _k = {
            "PriEsc": {
                "q": "query", "h": "headers", "c": "cookies"
            },
            "UnAuth": {
                "q": "query_unauth", "h": "headers_unauth", "c": "cookies_unauth"
            }
        }
        q_pri = PrivilegeEscalation.get_modify_query(query_params, _k[mode_type]["q"])
        # 配置请求头
        h_pri = PrivilegeEscalation.get_modify_headers(headers_dict, _k[mode_type]["h"])
        cookies = PrivilegeEscalation.get_modify_cookies(_k[mode_type]["c"])
        return q_pri, h_pri, cookies
