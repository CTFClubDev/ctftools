import socket,select,sys,string,random

PORT=7000 #8000

operation = sys.argv[1]
if ":" in sys.argv[2]:
    ip_addr,PORT = sys.argv[2].split(":")
    PORT=int(PORT)
else:
    ip_addr = sys.argv[2]
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((ip_addr,PORT))

def idgen(N):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))

def Store(s,k,v,p):
    s.send(b"store\n")
    res=s.recv(1024)
    if not b"Enter key" in res:
        sys.stderr.write("Enter key error \n"+res.decode())
        exit(1)

    s.send(b"%s\n" % (k.encode()))
    res=s.recv(1024)
    if not b"Enter value" in res:
        sys.stderr.write("Enter value error \n"+res.decode())
        exit(2)

    s.send(b"%s\n" % (v.encode()))
    res=s.recv(1024)
    if not b"Enter pass" in res:
        sys.stderr.write("Stored error \n"+res.decode())
        exit(3)

    s.send(b"%s\n" % (p.encode()))
    res=s.recv(1024)
    if not b"Stored" in res:
        sys.stderr.write("Stored error \n"+res)
        exit(3)
    return 1
def Load(s,k,p):
    s.send(b"load\n")
    res=s.recv(1024)
    if not b"Enter key" in res:
        sys.stderr.write("Load error 0\n"+res.decode())
        exit(1)
    s.send(b"%s\n" % (k.encode()))
    res=s.recv(1024)
    if not b"Enter pass(blank if no)" in res:
        sys.stderr.write("Load error 1\n"+res.decode())
        exit(3)
    s.send(b"%s\n" % (p.encode()))
    res=s.recv(1024)
    if b"No such value or invalid password" in res:
        sys.stderr.write("Load error 2\n"+res.decode())
        exit(3)
    return res.decode().strip()
def List(s,pat):
    s.send(b"list\n")
    res=s.recv(1024)
    if not b"Enter pattern" in res:
        sys.stderr.write("Search error 0\n"+res.decode())
        exit(1)
    s.send(b"%s\n" % (pat.encode()))
    res=s.recv(1024)
    all_data = list(map(lambda x: x.decode().strip(),res.split(b",")))
    return all_data


if operation == "check":
    mkey = idgen(random.randrange(5,12))
    mval = idgen(random.randrange(20,64))
    Store(s,mkey,mval,"")
    res = Load(s,mkey,"")
    if res != mval:
        print("Saved val not eq to real",res,mval)
        exit(3)
    a=List(s,mkey[2:4])
    if not mkey in a:
        print("Cannot find key",mkey)
        exit(3)
    sys.stderr.write("Success\n")
    exit(0)

elif operation == "put":
    flagid = sys.argv[3]
    flag = sys.argv[4]
    mpass = idgen(random.randrange(20,64))
    Store(s,flagid,flag,mpass)
    res = List(s,flagid[2:4])
    if not flagid in res:
        print("Cannot find key",mkey)
        exit(3)
    print(f"{flagid},{mpass}")
    exit(0)
elif operation == "get":
    flagid,mpass = sys.argv[3].split(',')
    flag = sys.argv[4]
    res = List(s,flagid[2:4])
    if not flagid in res:
        print("Cannot find key",mkey)
        exit(3)
    res = Load(s,flagid,mpass)
    if res != flag:
        print("Invalid flag",mkey)
        exit(3)
    exit(0)

"""
python3 client_1.py put localhost SOME_KEY SOME_VAL
SOME_KEY

exitcode
0 - сохранено
1 - не сохранено
python3 client_1.py get localhost SOME_KEY SOME_VAL

exitcode
0 - значение совпало
1 - значение не совпало



"""
