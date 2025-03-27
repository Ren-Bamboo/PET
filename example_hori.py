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
    # 设置严格模式，严格模式更精准，但可能漏掉一些东西，且未授权访问将不再作为检测点
    PrivilegeEscalation.set_strict_mode()
    # 设置水平越权模式
    PrivilegeEscalation.set_hori_PE_mode()

    # 设置黑白名单
    white_list = ["*"]
    black_list = ["zhihu.com"]
    PrivilegeEscalation.set_white_list(white_list)
    PrivilegeEscalation.set_black_list(black_list)

    # 启动服务
    # myPS.start_server(host="127.0.0.1", port=78787)   # 更改默认端口
    myPS.start_server()
