FROM registry.cn-hangzhou.aliyuncs.com/web_sanic/domestic_image:latest
LABEL maintainer="<fengxianglei2026@163.com>"

WORKDIR /app

VOLUME ['./web_sanic', '/app']

COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/

COPY . .

EXPOSE 8000

CMD [ "python3", "CloudDM/server.py"]
