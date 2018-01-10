FROM python:3

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt; rm -f /tmp/requirements.txt

RUN apt-get update && apt-get install -y socat openssh-client

WORKDIR /app
COPY . /app/
CMD ["python", "webmux.py"]
STOPSIGNAL SIGINT
