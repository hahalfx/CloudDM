from sqlalchemy import Column, VARCHAR, CHAR, BLOB, Date, BIGINT, Float, DateTime, BigInteger
from sqlalchemy.orm import declarative_base

# 定义声明式模型的基类
Base = declarative_base()


# 设备表映射类
class Device(Base):
    __tablename__ = "tbl_device"

    # 设备表的列定义
    id = Column(VARCHAR(255), primary_key=True)
    name = Column(VARCHAR(255), nullable=False)
    type = Column(VARCHAR(30), nullable=False)
    hardware_model = Column(VARCHAR(30), nullable=False)
    hardware_sn = Column(VARCHAR(30), nullable=False)
    software_version = Column(VARCHAR(30), nullable=False)
    software_last_update = Column(Date, nullable=False)
    nic1_type = Column(VARCHAR(30))
    nic1_mac = Column(VARCHAR(17))
    nic1_ipv4 = Column(VARCHAR(15))
    nic2_type = Column(VARCHAR(30))
    nic2_mac = Column(VARCHAR(17))
    nic2_ipv4 = Column(VARCHAR(15))
    status = Column(VARCHAR(30), default='off-line', nullable=False)
    created_time = Column(BIGINT, nullable=False)
    last_updated_time = Column(BIGINT, nullable=False)

    # 重写__str__方法，返回设备对象的字典表示
    def __str__(self):
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "hardware_model": self.hardware_model,
            "hardware_sn": self.hardware_sn,
            "software_version": self.software_version,
            "software_last_update": str(self.software_last_update),  # 日期格式需要转换为字符串
            "nic1_type": self.nic1_type,
            "nic1_mac": self.nic1_mac,
            "nic1_ipv4": self.nic1_ipv4,
            "nic2_type": self.nic2_type,
            "nic2_mac": self.nic2_mac,
            "nic2_ipv4": self.nic2_ipv4,
            "status": self.status,
            "created_time": self.created_time,
            "last_updated_time": self.last_updated_time
        }


# 敏感数据信息单独建表
class Device_Password_Token(Base):
    __tablename__ = "tbl_device_password_token"

    id = Column(VARCHAR(255), primary_key=True)
    salt = Column(BLOB(128), nullable=False)
    password = Column(CHAR(64), nullable=False)
    token = Column(CHAR(8), nullable=False)
    created_time = Column(BIGINT, nullable=False)
    last_updated_time = Column(BIGINT, nullable=False)


# # 设备组表映射类
class Device_Group(Base):
    __tablename__ = "tbl_device_group"

    # 设备组表的列定义
    group_id = Column(VARCHAR(255), primary_key=True)
    group_name = Column(VARCHAR(255), nullable=False)
    group_description = Column(VARCHAR(255), nullable=True)
    created_time = Column(BIGINT, nullable=False)
    last_updated_time = Column(BIGINT, nullable=False)

    # 重写__str__方法，返回设备分组对象的字典表示
    def __str__(self):
        return {
            "group_id": self.group_id,
            "group_name": self.group_name,
            "group_description": self.group_description,
            "created_time": self.created_time,
            "last_updated_time": self.last_updated_time
        }


# 设备与分组关系表映射类
class Device_Group_Relationship(Base):
    __tablename__ = "tbl_device_group_relationship"

    # 设备组关系表的列定义
    relationship_id = Column(VARCHAR(255), primary_key=True)
    id = Column(VARCHAR(255), nullable=False)
    group_id = Column(VARCHAR(255), nullable=False)
    created_time = Column(BIGINT, nullable=False)
    last_updated_time = Column(BIGINT, nullable=False)

    # 重写__str__方法，返回设备与设备分组关系对象的字典表示
    def __str__(self):
        return {
            "relationship_id": self.relationship_id,
            "id": self.id,
            "group_id": self.group_id,
            "created_time": self.created_time,
            "last_updated_time": self.last_updated_time
        }


# 设备状态信息表映射类
class Device_Status(Base):
    __tablename__ = "tbl_device_status"

    # 设备状态信息表列定义
    id = Column(VARCHAR(255), primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    user_cpu_time = Column(Float, nullable=False)
    system_cpu_time = Column(Float, nullable=False)
    idle_cpu_time = Column(Float, nullable=False)
    io_wait_cpu_time = Column(Float, nullable=False)
    total_memory = Column(BigInteger, nullable=False)
    free_memory = Column(BigInteger, nullable=False)
    used_memory = Column(BigInteger, nullable=False)
    total_disk = Column(BigInteger, nullable=False)
    used_disk = Column(BigInteger, nullable=False)
    free_disk = Column(BigInteger, nullable=False)

    def __str__(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "user_cpu_time": self.user_cpu_time,
            "system_cpu_time": self.system_cpu_time,
            "idle_cpu_time": self.idle_cpu_time,
            "io_wait_cpu_time": self.io_wait_cpu_time,
            "total_memory": self.total_memory,
            "free_memory": self.free_memory,
            "used_memory": self.used_memory,
            "total_disk": self.total_disk,
            "used_disk": self.used_disk,
            "free_disk": self.free_disk
        }
