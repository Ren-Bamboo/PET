import socket
import struct
import time
import threading
from concurrent.futures import ThreadPoolExecutor


class CloseFlag:
    def __init__(self):
        self.close_flag = False                     # socket关闭标志
        self.close_flag_lock = threading.Lock()     # 对应的互斥同步锁


class ProxyServer:

    def __init__(self):
        self.socket_count = 5
        self.handle_func = None
        self.executor = ThreadPoolExecutor(max_workers=20)

    def set_handle_func(self, handle_func):
        self.handle_func = handle_func

    def start_server(self, host='127.0.0.1', port=16166):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))
        server.listen(self.socket_count)
        print(f"Listening on {host}:{port}...")

        while True:
            sc_socket, addr = server.accept()
            print("处理addr请求：", addr)
            # 设置超时时间，与心跳包协作
            # sc_socket.settimeout(3)
            # 启动线程处理
            threading.Thread(target=self.work, args=(sc_socket,), daemon=True).start()

    def heart_pack(self, socket_, cf_ob: CloseFlag):
        while True:
            try:
                socket_.sendall(struct.pack('!BI', 0, 0))
                print("发送心跳包")
            except Exception as e:
                print("心跳包异常", e)
                self.close_socket(socket_, cf_ob)  # 关闭套接字
                break
            # 心跳包间隔2秒
            time.sleep(2)
        print("心跳包停止发送")

    def close_socket(self, socket_, cf_ob: CloseFlag):
        cf_ob.close_flag_lock.acquire()
        if not cf_ob.close_flag:
            cf_ob.close_flag = True
            socket_.close()
            print("socket close")
        cf_ob.close_flag_lock.release()

    def recv_data(self, socket_, data_length):
        received_data = b""
        while len(received_data) < data_length:
            try:
                chunk = socket_.recv(data_length - len(received_data))
            except Exception as e:
                print("接收数据发生错误：", e)
                # 发生错误，返回失败
                return received_data, False
            if not chunk:
                break
            received_data += chunk
        return received_data, True

    def handle_business(self, received_data):
        # 根据用户设置的方法处理该数据流
        if self.handle_func:
            # 使用线程池解决
            # self.handle_func(received_data)
            self.executor.submit(self.handle_func, received_data)
            # queued_tasks = self.executor._work_queue.qsize()
            # print("当前线程池中有：{}个任务".format(queued_tasks))

    def work(self, sc_socket, heart=False):
        # 针对当前sockets，维持一个心跳包，接收心跳包和业务数据
        cf_ob = CloseFlag()

        # 心跳线程启动
        if heart:
            threading.Thread(target=self.heart_pack, args=(sc_socket, cf_ob), daemon=True).start()

        # 处理业务逻辑
        while True:
            try:
                # 接收TL头部信息
                header = sc_socket.recv(5)
                # print("接收header:", header)
            except Exception as e:
                print("接收头部失败", e)
                self.close_socket(sc_socket, cf_ob)
                break
            if len(header) < 5:
                print("头部不完整，连接可能关闭")
                self.close_socket(sc_socket, cf_ob)
                break
            # 解析 Type 和 Length
            data_type, data_length = struct.unpack('!BI', header)

            # 根据Type走不同处理流程
            if data_type == 1:  # 处理业务
                try:
                    received_data, flag = self.recv_data(sc_socket, data_length)  # 接收的字节数据
                except Exception as e:
                    print("接收数据失败：", e)
                    self.close_socket(sc_socket, cf_ob)
                    break
                if not flag:  # 接收数据发生错误
                    self.close_socket(sc_socket, cf_ob)
                    break
                self.handle_business(received_data)
            elif data_type == 0:  # 心跳包
                print("收到心跳包")
                continue
            else:  # 未知type
                print("未知类型")
                self.close_socket(sc_socket, cf_ob)
                break
        print("work done：")


if __name__ == "__main__":
    myPS = ProxyServer()
    myPS.start_server()
