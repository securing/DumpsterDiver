FROM python:3.6.5-alpine

ADD requirements.txt ./
ADD *.py ./
ADD *.yaml ./

RUN pip install --no-cache-dir -r requirements.txt && \
    chmod +x DumpsterDiver.py && \
    mkdir -p /var/log/dumpsterdiver

ENTRYPOINT ["python","DumpsterDiver.py"]
