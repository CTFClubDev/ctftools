FROM ubuntu
RUN apt-get update
RUN apt-get install -y python3
RUN mkdir /home/task
# COPY serv_1.py /home/task/
WORKDIR /home/task/

ENTRYPOINT ["python3","serv_1.py"]
#CMD sleep 100000
