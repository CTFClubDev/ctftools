FROM ubuntu
RUN apt-get update
RUN apt-get install -y python3
RUN mkdir /home/task
COPY client_1.py /home/task/
WORKDIR /home/task/

ENTRYPOINT ["python3", "./client_1.py"] 
