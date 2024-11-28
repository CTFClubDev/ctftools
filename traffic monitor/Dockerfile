FROM ubuntu
RUN apt update
RUN apt install -y python3
RUN apt install -y python3-pip
RUN apt install  -y libnfnetlink-dev libnetfilter-queue-dev
RUN pip3 install flask NetfilterQueue scapy Flask-BasicAuth
RUN pip3 install pytz
WORKDIR /home/net
ENTRYPOINT ["python3","traffic_block.py"]
