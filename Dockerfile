FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./

ENV MCP_BIND_HOST=0.0.0.0 \
    MCP_BIND_PORT=8787 \
    MCP_DATA_DIR=/data

VOLUME /data
EXPOSE 8787

CMD ["python", "server.py"]
