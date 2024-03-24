from logging.handlers import TimedRotatingFileHandler
import logging

# 设置日志格式
log_format = '[%(asctime)s] [%(levelname)s] %(message)s'
# 创建 TimedRotatingFileHandler 处理器，每天创建一个新的日志文件，保留最近 7 天的日志文件
timed_handler = TimedRotatingFileHandler(filename="app.log", when="midnight", interval=1, backupCount=7)
timed_handler.setFormatter(logging.Formatter(log_format))

# 获取根日志记录器，并添加处理器
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(timed_handler)
