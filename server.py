import json
from sqlalchemy import and_
from sqlalchemy.exc import SQLAlchemyError
from models import Device, Device_Group, Device_Group_Relationship, Device_Password_Token, Device_Status, Base
from sqlalchemy.orm import sessionmaker
from snowflake import SnowflakeGenerator
import time
from sanic import Sanic, response
from sanic.request import Request
from sanic.response import json as json_response
import re
from logger_config import logger
from db_config import engine
from utils import generate_random_key, hash_salt_password, random, string
from secure_token_manager import SecureTokenManager  # 假设你有一个处理令牌的类

# 异常处理：尝试在指定的引擎上创建元数据中定义的所有表
try:
    Base.metadata.create_all(engine)
    logger.info("数据库表创建成功")
except SQLAlchemyError as e:
    logger.error(f"数据库表创建失败: {e}")

# 雪花算法ID生成器，机器ID设置为 1
gen = SnowflakeGenerator(1)
# 创建 Sanic 应用
app = Sanic("CloudDM")
# JSON 形式输出异常
app.config.FALLBACK_ERROR_FORMAT = "json"

#still in develop
# 使用专门的类来管理令牌和设备状态
token_manager = SecureTokenManager()

#token_list = []
# 在 echo 函数外部定义一个字典用于存储设备的最后一次心跳时间
device_last_heartbeat = {}
device_ws_mapping = {}


# 基于预定义的响应 websocket 的PDU 构建的简化发送的函数
async def send_ws_resp(ws, method, result):
    await ws.send(json.dumps({"method": method, "result": result}, ensure_ascii=False))


# 发送标准的 API http 响应格式
def send_http_resp(status, message, data=None):
    resp = {"status": status, "message": message} if data is None else {"status": status, "message": message,
                                                                        "data": data}
    return response.json(resp)


# 处理异常,将数据库事务回滚并将异常信息记录到日志中，并返回异常响应
def handle_exception(session, e):
    session.rollback()
    logger.error(str(e))
    return send_http_resp(0, str(e))


async def authenticate_ws(request: Request):
    match = re.search(r'auth=(\w+)', request.url)
    if match:
        token = match.group(1)
        # 使用 Token 管理器来验证 Token
        device_id = token_manager.validate_token(token)
        if device_id:
            return True  # 认证成功
        else:
            # 认证失败，可以返回错误信息或者做相应的日志记录
            return json_response({"error": "Invalid or expired token"}, status=401)
    # 如果 URL 中没有 token
    return json_response({"error": "Authentication token required"}, status=401)


async def handle_heartbeat(ws, heartbeat_data):
    try:
        device_id = heartbeat_data["id"]
        device_ws_mapping[device_id] = ws
        current_timestamp = int(time.time()) * 1000
        # 在这里可以根据需要处理收到的心跳数据，例如存入数据库、更新设备状态等
        device_status_data = \
            Device_Status(
                id=heartbeat_data["id"],
                timestamp=heartbeat_data["timestamp"],
                user_cpu_time=heartbeat_data["cpu"]["user"],
                system_cpu_time=heartbeat_data["cpu"]["system"],
                idle_cpu_time=heartbeat_data["cpu"]["idle"],
                io_wait_cpu_time=heartbeat_data["cpu"]["io_wait"],
                total_memory=heartbeat_data["memory"]["total"],
                free_memory=heartbeat_data["memory"]["free"],
                used_memory=heartbeat_data["memory"]["used"],
                total_disk=heartbeat_data["disk"]["total"],
                used_disk=heartbeat_data["disk"]["used"],
                free_disk=heartbeat_data["disk"]["free"]
            )
        app.ctx.db.add(device_status_data)
        app.ctx.db.commit()
    # 在这里你可以继续处理其他业务逻辑，如果需要的话
    except Exception as e:
        # 处理数据库操作异常
        logger.error(f"数据库操作异常: {e}")
        # 更新设备的最后心跳时间
        device_last_heartbeat[device_id] = current_timestamp
        # 构建响应消息，如果需要的话
        # response_data = {
        #     "method": "HEARTBEAT_RESPONSE",
        #     "data": "Received heartbeat successfully"
        # }
        await send_ws_resp(ws, "HEARTBEAT_RESPONSE", "Received heartbeat successfully")


async def send_command_to_device(device_id, command):
    ws = device_ws_mapping[device_id]
    # 向设备发送指令
    await send_ws_resp(ws, "COMMAND", command)


# 在服务器启动前设置数据库连接
@app.listener("before_server_start")
async def setup_db(app, loop):
    app.ctx.db = sessionmaker(autoflush=False, bind=engine)()


# 在服务器停止后关闭数据库连接
@app.listener("after_server_stop")
async def teardown_db(app, loop):
    app.ctx.db.close()


# 记录请求信息到日志文件的中间件
@app.middleware("request")
async def logging_request(request):
    logging_req = f"[srv] [req] ({request.method} {request.path}) {request.json}" if request.json is not None \
        else f"[srv] [req] ({request.method} {request.path}) "
    logger.info(logging_req)


# 南向身份验证中间件监听
@app.middleware("request")
async def auth_ws_token(request):
    if re.search(r'/echo', request.url):
        if await authenticate_ws(request):
            return
        else:
            return response.text('Unauthorized', status=401)


# 记录响应信息到日志文件的中间件
@app.middleware("response")
async def logging_response(request, response):
    resp = json.loads(response.body.decode("utf-8"))
    logging_resp = f"[srv] [resp] ({request.method} {request.path}) {resp}"
    logger.info(logging_resp)


# 获取所有设备的信息的端点
@app.get("/v1/devices", ignore_body=False)
async def get_devices(request):
    try:
        devices = app.ctx.db.query(Device).all()
        return send_http_resp(1, "设备查询成功", {"devices": [device.__str__() for device in devices]})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 根据设备ID获取设备信息的端点
@app.get("/v1/device/<device_id:\d+>", ignore_body=False)
async def get_device_by_device_id(request, device_id):
    try:
        device = app.ctx.db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return send_http_resp(0, "设备id不存在")
        return send_http_resp(1, "设备信息查询成功", {"device": device.__str__()})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 根据设备类型和硬件序列号获取设备信息的端点
@app.get("/v1/device", ignore_body=False)
async def get_devices_by_type_and_sn(request):
    try:
        data = request.json
        type = data.get("type")
        hardware_sn = data.get("hardware_sn")
        devices = app.ctx.db.query(Device).filter(and_(Device.type == type, Device.hardware_sn == hardware_sn)).all()
        if not devices:
            return send_http_resp(0, "设备信息查询失败")
        return send_http_resp(1, "设备信息查询成功", {"devices": [device.__str__() for device in devices]})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 根据设备ID获取设备及其分组信息的端点
@app.get("/v1/device_groups/<device_id:\d+>", ignore_body=False)
async def get_device_groups_by_device_id(request, device_id):
    try:
        device = app.ctx.db.query(Device).filter_by(id=device_id).first()
        if not device:
            return send_http_resp(0, "设备id不存在")
        group_id_list = app.ctx.db.query(Device_Group_Relationship.group_id).filter(
            Device_Group_Relationship.id == device_id).all()
        if not group_id_list:
            return send_http_resp(0, "设备不属于任何分组")
        return send_http_resp(1, "设备及其设备分组查询成功", {"device": device.__str__(), "groups": [
            app.ctx.db.query(Device_Group).filter_by(group_id=group_id[0]).one().__str__() for group_id in
            group_id_list]})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 获取所有设备和设备分组的端点
@app.get("/v1/devices_groups")
async def get_devices_groups(request):
    try:
        devices = app.ctx.db.query(Device).all()
        groups = app.ctx.db.query(Device_Group).all()
        return send_http_resp(1, "设备和设备分组查询成功",
                              {"devices": [device.__str__() for device in devices],
                               "groups": [group.__str__() for group in groups]})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 根据设备ID获取设备分组的端点
@app.get("/v1/groups/<device_id:\d+>")
async def get_groups_by_device_id(request, device_id):
    try:
        device = app.ctx.db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return send_http_resp(0, "设备id不存在")
        group_id_list = app.ctx.db.query(Device_Group_Relationship.group_id).filter(
            Device_Group_Relationship.id == device_id).all()
        if not group_id_list:
            return send_http_resp(0, "设备不属于任何分组")
        return send_http_resp(1, "设备分组查询成功", {
            "groups": [app.ctx.db.query(Device_Group).filter(Device_Group.group_id == group[0]).one().__str__() for
                       group in group_id_list]})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 根据分组ID获取设备分组的端点
@app.get("/v1/group/<group_id:\d+>")
async def get_group_by_group_id(request, group_id):
    try:
        group = app.ctx.db.query(Device_Group).filter(Device_Group.group_id == group_id).first()
        if not group:
            return send_http_resp(0, "设备分组id不存在")
        return send_http_resp(1, "设备分组查询成功", group.__str__())
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 获取所有设备分组的端点
@app.get("/v1/groups")
async def get_groups(request):
    try:
        groups = app.ctx.db.query(Device_Group).all()
        return send_http_resp(1, "设备分组信息查询成功", {"groups": [group.__str__() for group in groups]})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 根据分组ID获取设备分组下的设备的端点
@app.get("/v1/devices_in_group/<group_id:(\d+\d*)>")
async def get_devices_by_group_id(request, group_id):
    try:
        group = app.ctx.db.query(Device_Group).filter(Device_Group.group_id == group_id).first()
        if not group:
            return send_http_resp(0, "设备分组id不存在")
        device_id_list = app.ctx.db.query(Device_Group_Relationship.id).filter(
            Device_Group_Relationship.group_id == group_id).all()
        if not device_id_list:
            return send_http_resp(0, "该设备分组下无任何设备")
        return send_http_resp(1, "设备分组下的设备信息查询成功", {"group": group.__str__(), "devices": [
            app.ctx.db.query(Device).filter(Device.id == device[0]).one().__str__() for device in device_id_list]})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 检查设备是否在指定分组中的端点
@app.get("/v1/is_device_in_group", ignore_body=False)
async def is_device_in_group(request):
    try:
        data = request.json
        device_id = data.get("id")
        group_id = data.get("group_id")
        device = app.ctx.db.query(Device).filter(Device.id == device_id).first()
        group = app.ctx.db.query(Device_Group).filter(Device_Group.group_id == group_id).first()
        if not device:
            return send_http_resp(0, "设备id不存在")
        if not group:
            return send_http_resp(0, "设备分组id不存在")
        relationship = app.ctx.db.query(Device_Group_Relationship).filter(
            and_(Device_Group_Relationship.id == device_id, Device_Group_Relationship.group_id == group_id)).first()
        if not relationship:
            return send_http_resp(0, "设备不在该设备分组下")
        return send_http_resp(1, "设备在该设备分组下", {"device": device.__str__(), "group": group.__str__(),
                                                        "relationship": relationship.__str__()})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 添加设备的端点
@app.post("/v1/devices")
async def add_devices(request):
    try:
        data = request.json
        device_id = next(gen)
        created_time = int(time.time() * 1000)  # 当前时间戳
        last_updated_time = int(time.time() * 1000)  # 当前时间戳
        password = generate_random_key(random.randint(16, 25))
        #原token生成方式
        #token = "".join([random.choice(string.ascii_letters + string.digits) for _ in range(8)])
        
        #新token生成方式
        token = token_manager.generate_token(device_id)

        salt, hashed_password = hash_salt_password(password)
        device = Device(
            id=str(device_id),
            name=data.get("name"),
            type=data.get('type'),
            hardware_model=data.get('hardware_model'),
            hardware_sn=data.get('hardware_sn'),
            software_version=data.get('software_version'),
            software_last_update=data.get('software_last_update'),
            nic1_type=data.get('nic1_type'),
            nic1_mac=data.get('nic1_mac'),
            nic1_ipv4=data.get('nic1_ipv4'),
            nic2_type=data.get('nic2_type'),
            nic2_mac=data.get('nic2_mac'),
            nic2_ipv4=data.get('nic2_ipv4'),
            status=data.get('status'),
            created_time=created_time,
            last_updated_time=last_updated_time
        )
        device_password_token = Device_Password_Token(
            id=str(device_id),
            salt=salt,
            password=hashed_password,
            token=token,
            created_time=created_time,
            last_updated_time=last_updated_time
        )
        app.ctx.db.add(device)
        app.ctx.db.add(device_password_token)
        app.ctx.db.commit()
        return send_http_resp(1, "设备信息添加成功", {"id": str(device_id), "password": password})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 添加设备分组的端点
@app.post("/v1/device_groups")
async def add_device_groups(request):
    try:
        data = request.json
        group_id = next(gen)
        group = Device_Group(
            group_id=str(group_id),
            group_name=data.get("group_name"),
            group_description=data.get("group_description"),
            created_time=int(time.time() * 1000),
            last_updated_time=int(time.time() * 1000),
        )
        app.ctx.db.add(group)
        app.ctx.db.commit()
        return send_http_resp(1, "设备分组信息添加成功", {"group_id": str(group_id)})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 添加设备与设备分组关系的端点
@app.post("/v1/device_group_relationship")
async def add_device_group_relationship(request):
    try:
        data = request.json
        device_id = data.get("id")
        group_id = data.get("group_id")
        device = app.ctx.db.query(Device).filter(Device.id == device_id).one()
        group = app.ctx.db.query(Device_Group).filter(Device_Group.group_id == group_id)
        if not device:
            return send_http_resp(0, "设备id不存在")
        if not group:
            return send_http_resp(0, "设备分组id不存在")
        relationship = Device_Group_Relationship(
            relationship_id=next(gen),
            id=device_id,
            group_id=group_id,
            created_time=int(time.time() * 1000),
            last_updated_time=int(time.time() * 1000),
        )
        app.ctx.db.add(relationship)
        app.ctx.db.commit()
        return send_http_resp(1, "添加设备与设备分组关系成功")
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 更新设备信息的端点
@app.put("/v1/devices")
async def update_devices(request):
    try:
        data = request.json
        device_id = data.get("id")
        data.update({"last_updated_time": int(time.time() * 1000)})
        rows = app.ctx.db.query(Device).filter(Device.id == device_id).update(data)
        if rows == 0:
            return send_http_resp(0, "设备id不存在")
        app.ctx.db.commit()
        return send_http_resp(1, "设备信息更新成功")
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 更新设备登录密码的端点
@app.put("/v1/device_password")
async def update_device_password(request):
    try:
        data = request.json
        device_id = data.get("id")
        password = data.get("password")
        if device_id is None or password is None:
            return send_http_resp(0, "请提供设备id和原来的密码")
        device = app.ctx.db.query(Device_Password_Token).filter_by(id=device_id).first()
        if not device:
            return send_http_resp(0, "设备id不存在")
        if hash_salt_password(password, device.salt)[1] != device.password:
            return send_http_resp(0, "提供的设备id或者密码错误")
        new_password = generate_random_key(random.randint(16, 25))
        new_salt, new_hashed_password = hash_salt_password(new_password)
        device.salt = new_salt
        device.password = new_hashed_password
        device.last_updated_time = int(time.time() * 1000)
        app.ctx.db.commit()
        return send_http_resp(1, "设备登录密码更新成功", {"password": new_password})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 更新设备分组信息的端点
@app.put("/v1/device_groups")
async def update_device_groups(request):
    try:
        data = request.json
        group_id = data.get("group_id")
        data.update({"last_updated_time": int(time.time() * 1000)})
        rows = app.ctx.db.query(Device_Group).filter_by(group_id=group_id).update(data)
        if rows == 0:
            return send_http_resp(0, "设备分组id不存在")
        app.ctx.db.commit()
        return send_http_resp(1, "设备分组信息更新成功")
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 删除设备信息的端点
@app.delete("/v1/devices")
async def delete_devices(request):
    try:
        data = request.json
        id_list = data.get("id_list")
        deleted_rows = app.ctx.db.query(Device).filter(Device.id.in_(id_list)).delete()
        if deleted_rows != len(id_list):
            app.ctx.db.rollback()
            return send_http_resp(0, "某个设备id不存在")
        app.ctx.db.query(Device_Group_Relationship).filter(Device_Group_Relationship.id.in_(id_list)).delete()
        app.ctx.db.query(Device_Password_Token).filter(Device_Password_Token.id.in_(id_list)).delete()
        app.ctx.db.commit()
        return send_http_resp(1, "设备信息删除成功", id_list)
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 删除设备分组信息的端点
@app.delete("/v1/groups")
async def delete_device_groups(request):
    try:
        data = request.json
        group_id_list = data.get("group_id_list")
        deleted_rows = app.ctx.db.query(Device_Group).filter(Device_Group.group_id.in_(group_id_list)).delete()
        if deleted_rows != len(group_id_list):
            app.ctx.db.rollback()
            return send_http_resp(0, "某个设备分组id不存在")
        app.ctx.db.query(Device_Group_Relationship).filter(
            Device_Group_Relationship.group_id.in_(group_id_list)).delete()
        app.ctx.db.commit()
        return send_http_resp(1, "设备分组信息删除成功", group_id_list)
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 删除设备的所属的全部设备分组的端点
@app.delete("/v1/groups_in_device")
async def delete_groups_in_device(request):
    try:
        data = request.json
        device_id = data.get("id")
        device = app.ctx.db.query(Device).filter_by(id=device_id).first()
        if not device:
            return send_http_resp(0, "设备id不存在")
        group_id_list = app.ctx.db.query(Device_Group_Relationship.group_id).filter(
            Device_Group_Relationship.id == device_id).all()
        deleted_rows = app.ctx.db.query(Device_Group_Relationship).filter(
            Device_Group_Relationship.id == device_id).delete()
        if deleted_rows == 0:
            app.ctx.db.rollback()
            return send_http_resp(0, "设备不属于任何分组")
        app.ctx.db.commit()
        return send_http_resp(1, "设备所属全部设备分组删除成功", {"device": device.__str__(), "deleted_groups": [
            app.ctx.db.query(Device_Group).filter_by(group_id=group_id[0]).one().__str__() for group_id in
            group_id_list]})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 删除设备分组下的设备信息的端点
@app.delete("/v1/devices_in_group")
async def delete_devices_in_group(request):
    try:
        data = request.json
        group_id = data.get("group_id")
        group = app.ctx.db.query(Device_Group).filter_by(group_id=group_id).first()
        if not group:
            return send_http_resp(0, "设备分组id不存在")
        device_id_list = app.ctx.db.query(Device_Group_Relationship.id).filter(
            Device_Group_Relationship.group_id == group_id).all()
        deleted_rows = app.ctx.db.query(Device_Group_Relationship).filter(
            Device_Group_Relationship.group_id == group_id).delete()
        if deleted_rows == 0:
            app.ctx.db.rollback()
            return send_http_resp(0, "设备分组下无任何设备")
        app.ctx.db.commit()
        return send_http_resp(1, "设备分组下的设备信息删除成功", {"group": group.__str__(), "deleted_devices": [
            app.ctx.db.query(Device).filter_by(id=device_id[0]).one().__str__() for device_id in device_id_list]})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 删除设备与设备分组的关系的端点
@app.delete("/v1/device_group_relationship")
async def delete_device_group_relationship(request):
    try:
        data = request.json
        if data.get("relationship_id") is not None:
            deleted_rows = app.ctx.db.query(Device_Group_Relationship).filter_by(
                relationship_id=data.get("relationship_id")).delete()
            if deleted_rows == 0:
                return send_http_resp(0, "关系id不存在")
            app.ctx.db.commit()
            return send_http_resp(1, "设备与设备分组关系删除成功")
        elif data.get("id") and data.get("group_id"):
            deleted_rows = app.ctx.db.query(Device_Group_Relationship).filter_by(id=data.get('id'),
                                                                                 group_id=data.get("group_id")).delete()
            if deleted_rows == 0:
                return send_http_resp(0, "设备与设备分组关系不存在")
            app.ctx.db.commit()
            return send_http_resp(1, "设备与设备分组关系删除成功")
    except Exception as e:
        return handle_exception(app.ctx.db, e)


# 在北向接口中的某个路由处理函数，例如设备管理服务的下发指令接口
@app.post("/v1/devices/command")
async def send_command(request):
    # 从请求中获取设备ID和指令
    request_data = request.json
    device_id = request_data.get("id")
    command = request_data.get("command")

    # 验证请求中是否包含必要的参数
    if not device_id or not command:
        return response.json({"status": 0, "message": "Invalid request data"})

    # 调用函数下发指令到设备
    await send_command_to_device(device_id, command)

    return response.json({"status": 1, "message": "Command sent successfully"})


@app.websocket("/echo")
async def echo(request, ws):
    # 假设 authenticate_ws 已经在握手阶段被调用并验证了 token
    authenticated = await authenticate_ws(request)
    if not authenticated:
        await ws.close(reason="Authentication failed")
        return

    while True:
        biz_data = await ws.recv()
        try:
            biz_dict = json.loads(biz_data)
        except ValueError:
            logger.info("Received data is not a valid JSON string")
            await send_ws_resp(ws, "ERROR", "Received data is not a valid JSON string")
            continue

        # Process heartbeat message
        if biz_dict.get("method") == "HEARTBEAT" and "data" in biz_dict:
            await handle_heartbeat(ws, biz_dict["data"])
        else:
            logger.info("Invalid request, please check the request fields")
            await send_ws_resp(ws, "ERROR", "Invalid request, please check the request fields")

# 南向身份验证
@app.post("/auth")
async def auth(request):
    session = app.ctx.db.session()
    try:
        data = request.json
        device_id = data.get("id")
        password = data.get("password")

        device = session.query(Device_Password_Token).filter(Device_Password_Token.id == device_id).first()
        if not device:
            return send_http_resp(0, "设备未找到")

        # 确保 device.salt 和 device.password 存在，并正确使用它们进行密码验证
        if hash_salt_password(password, device.salt)[1] != device.password:
            return send_http_resp(0, "密码错误")

        #token_list.append(device.token)
        return send_http_resp(1, "验证成功", {"token": device.token})
    except Exception as e:
        return handle_exception(app.ctx.db, e)


if __name__ == "__main__":
    # 启动 Sanic 应用，为了避免多进程的额外问题，这里使用单进程模式
    app.run(host="0.0.0.0", port=8000, single_process=True)
    logger.info("127.0.0.1:8000 has initialized")
