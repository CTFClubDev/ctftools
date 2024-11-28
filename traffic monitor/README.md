
*** How to run

1. sudo docker compose up --build -d
2. Fill service info in file service.py
for example
`{'name': "test_http", 'proto': "TCP", 'port':8081},`
Service with name test_http via tcp/8081 on your host
3. Forward all traffic for service to NFQUEUE number 31337
`sudo python3 a test_http`
After this all traffic starts to go to NFQUEUE number 31337
4. Go to localhost:5555, (default creds are admin:qwe)
