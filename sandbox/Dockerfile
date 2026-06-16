FROM swr.cn-north-4.myhuaweicloud.com/claw/scienceclaw-sandbox:release-v0.0.4

WORKDIR /workspace
RUN id sandboxuser >/dev/null 2>&1 || useradd -m sandboxuser
COPY requirements.txt /workspace/requirements.txt
RUN pip install --no-cache-dir -r /workspace/requirements.txt
COPY openclaw_stub.py /workspace/openclaw_stub.py
COPY entrypoint.sh /workspace/entrypoint.sh
RUN chmod +x /workspace/entrypoint.sh && chown -R sandboxuser:sandboxuser /workspace
USER sandboxuser
ENTRYPOINT ["/workspace/entrypoint.sh"]
