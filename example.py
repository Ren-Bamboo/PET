from LocalServer import ProxyServer
from PrivilegeEscalation import PrivilegeEscalation


if __name__ == '__main__':

    myPS = ProxyServer()

    # 设置处理函数
    handle_fun = PrivilegeEscalation.run
    myPS.set_handle_func(handle_fun)

    # 设置配置文件路径
    PrivilegeEscalation.set_config_path("./config.yaml")
    # 设置保存目录
    PrivilegeEscalation.set_save_path('./output/')

    # 启动服务
    # myPS.start_server(host="127.0.0.1", port=78787)   # 更改默认端口
    myPS.start_server()
