# 使用指定的基础镜像开始构建
FROM registry.cn-hangzhou.aliyuncs.com/web_sanic/domestic_image:latest

# 维护者信息
LABEL maintainer="fengxianglei2026@163.com"

# 设置工作目录。如果目录不存在，Docker 会自动为你创建它。
WORKDIR /app

# 定义挂载点。注意 Dockerfile 中的 VOLUME 指令不支持使用相对路径。
VOLUME ["/app"]

# 将 requirements.txt 文件复制到容器的工作目录中
COPY requirements.txt ./

# 使用阿里云的 Python 包镜像源来加速包的下载。
RUN pip3 install --no-cache-dir -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/

# 将当前目录下的所有文件复制到容器的工作目录中
COPY . ./CloudDM

# 声明容器运行时监听的端口
EXPOSE 8000

# 容器启动时执行的命令
CMD ["python3", "CloudDM/server.py"]

