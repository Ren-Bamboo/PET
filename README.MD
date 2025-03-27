# 越权测试工具

## 使用方法

### 1、环境配置
~~~
0、安装python依赖: **pip install -r requirements.txt**
1、将 "jython-2.7.3.jar" 文件配置到Burp的python环境中
2、将 "BurpPlugin.py" 文件作为扩展添加到Burp中
3、更改 "config.yaml" 配置文件，按需设置需要添加的"权限参数"
~~~

### 必看
~~~
1、提供了两个模板，可以直接使用
    一个针对水平越权(example_hori.py)
    一个针对垂直越权(example_ver.py)
    
2、设置严格模式会更精准，适合复杂场景（最好默认使用）
    使用代码：PrivilegeEscalation.set_strict_mode()
    但如果是测试管理后台越权等场景，可以不使用严格模式
    
3、水平越权和垂直越权不能同时使用
    即，使用了：PrivilegeEscalation.set_hori_PE_mode()
    就表示使用水平越权测试
    
4、在使用该工具测试时，一定要注意“鉴权”参数是否设置正确且有效，
    如：cookies 是否有效
    
5、目前不支持修改请求体中来测试水平越权
~~~

### 2、运行
~~~
python example.py

注意：先启动本地 example.py，再重新打开Burp中的插件
~~~

### 3、Q&S
~~~
1、BurpPlugin.py 文件中有标红的地方，不用管，直接导入burp中
2、先启动本地的服务，在激活burp中的插件
3、注意，在进行垂直越权测试时，config.yaml文件中配置低权限账户信息
~~~

## 文件说明
~~~
这个工具将走burp代理的http流量镜像一份到本地进行越权测试

BurpPlugin.py           // 文件为burp插件（需要配合当前目录下的jypython使用）
jython-2.7.3.jar        // 用于配置burp的jython环境
LocalServer.py          // 本地流量接收服务
PrivilegeEscalation.py  // 越权测试主文件
example.py              // 示例文件
~~~
## 更改配置
~~~
burp与本地服务使用的默认端口为：16166

如果需要更改端口:
1、自行修改 BurpPlugin.py 中的端口，然后添加到burp的插件中
2、在 myPS.start_server() 中指定ip与端口（见example.py）
~~~
## 改进
~~~
1、目前文档不太完善，但已经可以用于使用，后续将给出更清晰的文档
2、后续将给出鉴别是否存在越权的接口，增加灵活性
~~~