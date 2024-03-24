import sys
import logging
import json
import requests

from sanic import Request, text, response
# 对端关闭时产生的异常​
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect
from websocket import create_connection, WebSocketConnectionClosedException  # 引入WebSocket关闭异常

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
    try:
        if command == "reboot":
            logger.info("执行云端下发指令: '重启'")
            subprocess.run(["shutdown", "/r", "/t", "1"], check=True)
        elif command.startswith("sftp_upload "):
            local_path = "device_windows.log"
            logger.info("执行云端下发指令: '日志上传'")
            # 这里假设 sftp_upload 函数已被定义，负责上传文件
            sftp_upload(local_path)
        else:
            logger.warning(f"未知指令: {command}")
    except subprocess.CalledProcessError as e:
        logger.error(f"执行命令时出错: {e}")
    except Exception as e:
        logger.error(f"执行指令过程中发生异常: {e}")


# 添加 sftp_upload 函数，用于实际执行上传操作
def sftp_upload(local_path):
    # 设置 sftp 连接参数
    host = "xxx"  # 修改成服务器地址
    port = 22
    username = "mysftp"
    password = "xx123456"
    
    # 确保在函数调用之前已定义 'id'
    global id

    try:
        # 检查本地文件是否存在
        if not os.path.isfile(local_path):
            raise FileNotFoundError(f"{local_path} 文件不存在")
        
        # 创建 sftp 连接
        with paramiko.Transport((host, port)) as transport:
            transport.connect(username=username, password=password)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                # 构建远程文件路径
                remote_target = f"/upload/device_windows_{id}.log"
                sftp.put(local_path, remote_target)
                logger.info(f"成功上传日志文件 {local_path} 到远程服务器: {remote_target}")
    except FileNotFoundError as e:
        logger.error(f"本地文件错误: {e}")
    except paramiko.SSHException as e:
        logger.error(f"建立SFTP连接失败: {e}")
    except Exception as e:
        logger.error(f"上传文件时发生未知错误: {e}")



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
            # 发送心跳消息
            send_req(ws_client, "HEARTBEAT", get_system_status())

            # 接收并解析服务端的响应
            recv_data = json.loads(ws_client.recv())
            if recv_data["method"] == "COMMAND":
                execute_command(recv_data["result"])
            print(f"RECV: {recv_data}")
            logger.info(f"RECV: {recv_data}")
            logger.info("收到心跳回复")
            
            # 等待一段时间，这里假设是5秒，可以根据实际情况调整
            time.sleep(5)

        except WebSocketConnectionClosedException:
            logger.error("连接已关闭，退出心跳循环")
            break
        except json.JSONDecodeError:
            logger.error("解析服务端响应失败")
        except Exception as e:
            logger.error(f"发生异常：{e}")

    logger.info("心跳循环退出")




def auth_biz(ws_client):
    try:
        # 从命令行获取用于身份验证的 SN 与 password
        serial_number = input("SN: ")
        password = input("Password: ")

        # 构建 PDU 并发送
        send_req(ws_client, "AUTH_DEVICE", {"sn": serial_number, "password": password})
        logger.info("成功发送身份验证消息")

        # 接收并解析响应的数据，判断身份验证是否成功
        auth_recv = ws_client.recv()
        auth_dict = json.loads(auth_recv)

        if auth_dict.get("method") == "AUTH_DEVICE" and auth_dict.get("result") == "OK":
            logger.info("身份验证成功")
            print("身份验证成功")
            return True
        else:
            logger.warning("身份验证失败")
            print("身份验证失败")
            return False

    except json.JSONDecodeError as e:
        logger.error(f"解析身份验证响应失败: {e}")
        print("身份验证失败，响应格式错误")
    except Exception as e:
        logger.error(f"身份验证过程中发生异常: {e}")
        print("身份验证失败，发生未知错误")
    return False

def startup():
    url = "localhost:8000"
    id = input("ID: ")
    password = input("Password: ")

    headers = {"Content-Type": "application/json"}
    data = {
        "id": id,
        "password": password
    }

    try:
        logger.info(f"正在连接 {url}")
        response = requests.post(f'http://{url}/auth', headers=headers, data=json.dumps(data))

        # 检查响应是否包含 token
        if "token" not in response.json():
            print("登录失败")
            logger.error("登录失败")
            sys.exit()

        token = response.json()["token"]
        logger.info("通道建立成功")

        ws_url = f"ws://{url}/echo?auth={token}"
        try:
            with create_connection(ws_url) as ws_client:
                logger.info(f"鉴权通过, 成功连接到 {ws_url}")
                echo_biz(ws_client)
        except WebSocketConnectionClosedException as e:
            logger.error(f"WebSocket 连接关闭: {e}")
        except Exception as e:
            logger.error(f"连接 WebSocket 时发生错误: {e}")

    except requests.exceptions.RequestException as e:
        logger.error(f"连接到服务器时发生错误: {e}")
        sys.exit()

    logger.info("程序即将退出")

if __name__ == "__main__":
    startup()