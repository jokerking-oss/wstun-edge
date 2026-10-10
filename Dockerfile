# Koyeb 等支持 Docker 的平台用这个（Render 用 render.yaml 即可，不需要 Dockerfile）
FROM python:3.12-slim

WORKDIR /app

# 零依赖：只需要这一个文件
COPY edge_srv.py ./

# PaaS 会用自己的 PORT 覆盖掉这里的默认值（edge_srv.py 会自动读取）
ENV PORT=8080
EXPOSE 8080

# 不加 -u 也能跑，但加了日志实时性好（平台日志面板能看到）
CMD ["python", "-u", "edge_srv.py"]
