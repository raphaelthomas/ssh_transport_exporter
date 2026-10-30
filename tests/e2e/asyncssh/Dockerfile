FROM python:3.13-alpine
WORKDIR /app
COPY requirements.txt server.py ./
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt \
 && python -c "import asyncssh; asyncssh.generate_private_key('ssh-ed25519').write_private_key('ssh_host_ed25519_key')"
CMD ["python", "server.py"]
