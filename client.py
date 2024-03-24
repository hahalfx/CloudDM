import sys
import logging
import json
import requests
from sanic import Request, text, response
# 对端关闭时产生的异常​
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect
import time
import psutil  # 用于获取系统信息
import subprocess
import json
import os
import paramiko  # 用于 sftp 操作，需要安装 paramiko 库


# 设置日志系统
logger = logging.getLogger("mylogger")  
logger.setLevel(logging.INFO)  
file_handler = logging.FileHandler("device_windows.log", encoding='utf-8')  
formatter = logging.Formatter('%(asctime)s - %(message)s')  
logger.addHandler(file_handler)
logger.handlers[0].setFormatter(formatter)




# 在客户端代码中添加一个函数用于执行云端下发的指令
def execute_command(command):
    if command == "reboot":
        logger.info(f"执行云端下发指令: '重启'")
        subprocess.run(["shutdown", "/r", "/t", "1"], shell=True)
    elif command.startswith("sftp_upload "):
        local_path = "device_windows.log"
        logger.info(f"执行云端下发指令: '日志上传'")
        sftp_upload(local_path)
    else:
        print(f"Unknown command: {command}")

# 添加 sftp_upload 函数，用于实际执行上传操作
def sftp_upload(local_path):
    # 设置 sftp 连接参数
    host = "xxx"  #修改成服务器地址
    port = 22
    username = "mysftp"
    password = "xx123456"

    try:
        # 创建 sftp 连接
        with paramiko.Transport((host, port)) as transport:
            transport.connect(username=username, password=password)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                
                remote_target = "/upload/device_windows_"+id+".log"
                print(os.path.isfile(local_path))
                sftp.put(local_path, remote_target)
                logger.info(f"成功上传日志文件到远程服务器")
    except FileNotFoundError as e:
        logger.error(f"本地文件 {str(e)} 不存在")
    except Exception as e:
        logger.error(f"上传文件时发生错误: {str(e)}")



# 基于预定义的请求 PDU 构建的简化发送的函数​
def send_req(ws_client, method, data):
    ws_client.send(json.dumps({"method": method, "data": data}, ensure_ascii=False))


def get_system_status():
    # 获取系统状态信息，例如 CPU、内存、硬盘等
    cpu_info = psutil.cpu_times()
    memory_info = psutil.virtual_memory()
    disk_info = psutil.disk_usage('/')

    # 构建设备状态字典
    status = {
        "id":id,
        "timestamp": int(time.time()),  # 当前时间戳
        "cpu": {
            "user": cpu_info.user,
            "system": cpu_info.system,
            "idle": cpu_info.idle,
            "io_wait": getattr(cpu_info, 'iowait', 0) 
        },
        "memory": {
            "total": memory_info.total,
            "free": memory_info.available,
            "used": memory_info.used,
            "percent": memory_info.percent
        },
        "disk": {
            "total": disk_info.total,
            "used": disk_info.used,
            "free": disk_info.free,
            "percent": disk_info.percent
        }
    }

    return status

def echo_biz(ws_client):
    while True:
        try:
            send_req(ws_client, "HEARTBEAT", get_system_status())
            # 发送心跳消息

            # 接收并解析服务端的响应
            recv_data = json.loads(ws_client.recv())
            if recv_data["method"]=="COMMAND":
                execute_command(recv_data["result"])
            print(f"RECV: {recv_data}")
            logger.info(f"收到心跳回复")
            # 等待一段时间，这里假设是5秒，可以根据实际情况调整
            time.sleep(5)

        except ConnectionClosed:
            print("连接已关闭，退出心跳循环")
            break
        except Exception as e:
            print(f"发生异常：{e}")
            # 可以添加适当的异常处理逻辑

    logger.info("心跳循环退出")




def auth_biz(ws_client):
    # 从命令行获取用于身份验证的 SN 与 password 并构建 PDU 并发送​
    serial_number = input("SN: ")
    password = input("password: ")
    send_req(ws_client, "AUTH_DEVICE", {"sn": serial_number, "password": password})
    logger.info("成功发送身份验证消息")

    # 接收并解析响应的数据，判断身份验证是否成功​
    try:
        auth_recv = ws_client.recv()
    except ConnectionClosed:
        print("身份验证失败，对端主动关闭连接")
        return False

    auth_dict = json.loads(auth_recv)
    if (
        "method" in auth_dict
        and auth_dict["method"] == "AUTH_DEVICE"
        and "result" in auth_dict
        and auth_dict["result"] == "OK"
    ):
        print("身份验证成功")
        return True
    print("身份验证失败")
    return False

def startup():
    # url = sys.argv[1]
    url = "localhost:8000"
    id = input("ID: ")
    # id="7138402876879015936"
    password = input("password: ")
    # password="abc"

    headers = {"Content-Type": "application/json"}
    data = {
    "id": id ,
    "password": password
    }

    logger.info(f"正在连接 {url}")
    response = requests.post('http://'+url+'/auth',  headers=headers,data=json.dumps(data))
    #response.json把得到的json自动转化为字典

    if "token" not in response.json():
        print("login fail")
        sys.exit()
    token=response.json()["token"]
    logger.info(f"通道建立成功")
    # print(token)
    #ws://localhost:8000/ws
    #身份验证第二步协议
    #ws://127.0.0.1:8000/echo?auth=qeDextVx
    ws_url="ws://"+url+"/echo?auth="+token
    # print(ws_url)
    with connect(ws_url) as ws_client:

        logger.info(f"鉴权通过,成功连接到 {ws_url}")
        echo_biz(ws_client)
    logger.info("程序即将退出")

startup