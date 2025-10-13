FROM python:3.13-slim
WORKDIR /app
COPY check_secure.py check.py requirements.txt ./
RUN chmod +x *.py
RUN pip install --no-cache-dir -r requirements.txt
