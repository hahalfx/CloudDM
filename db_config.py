from sqlalchemy import MetaData, create_engine

# 创建一个元数据对象，用于保存与表和数据库相关的各种特性
metadata = MetaData()
# 数据库配置设置
db_config = {
    'host': 'localhost',
    'port': 5432,
    'user': 'postgres',
    'password': 'zczc@8888',
    'db': 'device_management_db'
}
# 使用配置创建数据库 URL
#database_url = f"mysql+mysqlconnector://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['db']}"
# 使用指定的数据库 URL 创建 SQLAlchemy 引擎
#engine = create_engine(database_url)
# 在指定引擎上创建元数据中定义的所有表

#使用postgres作为数据库
database_url = f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['db']}"
engine = create_engine('postgresql://username:password@host/dbname')
