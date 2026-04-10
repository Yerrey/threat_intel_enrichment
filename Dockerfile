FROM python:3.11-slim
WORKDIR  /app
COPY enrichment.py .
RUN pip install requests
CMD ["python", "enrichment.py"]