import socket,threading,select,sys,os,sqlite3

db_file = "db.sqlite3"
def init_database_file():
    if not os.path.isfile(db_file):
        with open(db_file, 'w') as file:
            file.write('')
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute(f'''CREATE TABLE messages(key TEXT,value TEXT, password TEXT)''')
        print("table created")
        conn.commit()
        conn.close()
init_database_file()

mutex = threading.Lock()
def load(k, p):
    with mutex:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute(f"SELECT value FROM messages WHERE key = '{k}' AND password = '{p}'")
        result = cursor.fetchone()

        conn.close()
        if result:
            return result[0]
        else:
            return None

def store(k, v, p):
    with mutex:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(f"INSERT INTO messages (key, value, password) VALUES ('{k}', '{v}', '{p}')")
        conn.commit()
        conn.close()

def search(pat):
    with mutex:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(f"SELECT key FROM messages WHERE key LIKE '%{pat}%'")
        results = cursor.fetchall()
        conn.close()

        return [res[0] for res in results]

def OnCMD(s,data):
    if b"store" in data:
        s.send(b"Enter key\n")
        mkey = s.recv(1024).decode().strip()
        s.send(b"Enter value\n")
        mval = s.recv(1024).decode().strip()
        s.send(b"Enter password(blank if no)\n")
        mpass = s.recv(1024).decode().strip()
        store(mkey,mval,mpass)
        s.send(b"Stored\n")
    elif b"load" in data:
        s.send(b"Enter key\n")
        mkey = s.recv(1024).decode().strip()
        s.send(b"Enter pass(blank if no)\n")
        mpass = s.recv(1024).decode().strip()
        res = load(mkey,mpass)
        if res:
            s.send(res.encode()+b"\n")
        else:
            s.send(b"No such value or invalid password\n")
    elif b"list" in data:
        s.send(b"Enter pattern\n")
        mkey_patt = s.recv(1024).decode().strip()
        res = search(mkey_patt)
        s.send(b",".join(map(lambda x: x.encode(),res))+b"\n")
    else:
        s.send(b"No such command\n")

def HandleConnect(s):
    inp_set = [s, sys.stdin]
    work=1
    while work:
        inputready, outputready, exceptready = select.select(inp_set, [], [], 10)
        for x in inputready:
            if x == s:
                data = s.recv(1024)
                if len(data)==0:
                    print("Data is nul")
                    work=0
                if b"exit" in data:
                    break
                if len(data)==0:
                    break;
                OnCMD(s,data)
    s.close()
SERVER_ADDRESS = ('0.0.0.0', 7000)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket .setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
server_socket.bind(SERVER_ADDRESS)
server_socket.listen(10)
print('server is running, please, press ctrl+c to stop')
while True:
    connection, address = server_socket.accept()
    print("new connection from {address}".format(address=address))
    t=threading.Thread(target=HandleConnect,args=(connection,))
    t.start()
    
