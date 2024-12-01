import subprocess as sp
import string,random,datetime,sys,time,threading,socket,select,traceback,json,os
import tabulate
import shutil

TIME_OFFSET=3
start_time = "01:20 01.12.2024"
end_time = "04:20 01.12.2024"
teams = [
        dict(name="team0",ip="localhost",start_port=0),
        dict(name="team1",ip="localhost",start_port=100),
        dict(name="team2",ip="localhost",start_port=200),
        ]

services= [dict(name="sqli",checker="../checker/checker.py",port=10000)]

params = dict(
    round_time=10,
    start_date=datetime.datetime.strptime(start_time,"%H:%M %d.%m.%Y"),
    end_date=datetime.datetime.strptime(end_time,"%H:%M %d.%m.%Y"),
    flag_port= 31337,
    scoreboard="scoreboard.txt",
    flag_lifetime= 100,
)
scoreboard = {}
saved_board="scoreboard.json"

def idgen(N):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))

def GenFlag():
    return "CTF{" + idgen(32)+'}'

def InitScoreboard():
    for t in teams:
        serv_status={}
        for s in services:
            serv_status[s['name']] = \
                dict(last_code_check=0,
                     last_mes_check=0,
                     total_check=0,
                     success_check=0,

                     last_code_put=0,
                     last_mes_put=0,
                     total_put=0,
                     success_put=0,

                     last_put_flag=[],
                     this_passed_flags=[],

                     last_code_get=0,
                     last_mes_get=0,
                     total_get=0,
                     success_get=0,

                     total_flags_stored=0,  # сколько флагов успешно сохранено на сервисе
                     total_flags_loss=0,    # сколько флагов не смогли получить с сервиса
                     total_flags_stealed=0, # сколько у нас украли
                     total_flags_hacked=0   # сколько мы украли
                     )
        scoreboard[t['name']] = serv_status
scoreboard_mutex = threading.Lock()
def LoadScoreboard():
    global scoreboard
    with scoreboard_mutex:
        scoreboard = json.load(open(saved_board))
def StoreScoreboard():
    global scoreboard
    with scoreboard_mutex:
        if os.path.isfile(saved_board):
            shutil.copyfile(saved_board, saved_board+".bak")
        json.dump(scoreboard,open(saved_board,"w"), sort_keys=True, indent=4)
        if os.path.isfile(saved_board+".bak"):
            os.unlink(saved_board+".bak")

if os.path.isfile(saved_board):
    LoadScoreboard()
else:
    InitScoreboard()

def CheckService(team,serv):
    team_port = team['start_port']+serv['port']
    if serv['checker'].endswith(".py"):
        res = sp.Popen(["python3",serv['checker'],"check",team['ip']+":"+str(team_port)],stdout=sp.PIPE,stderr=sp.PIPE)
    else:
        res = sp.Popen([serv['checker'],"check",team['ip']+":"+str(team_port)],stdout=sp.PIPE,stderr=sp.PIPE)
    r = res.communicate()
    code = res.returncode
    return code,r[0],r[1]

def CheckAllService():
    for serv in services:
        for t in teams:
            print(f"[CHECKER] Checking team {t} service {serv}")
            code,stdout,stderr = CheckService(t,serv)
            with scoreboard_mutex:
                scoreboard[t['name']][serv['name']]['last_code_check']=code
                scoreboard[t['name']][serv['name']]['last_mes_check']=(stdout.decode(),stderr.decode())
                scoreboard[t['name']][serv['name']]['total_check'] +=1
                if code == 0:
                    scoreboard[t['name']][serv['name']]['success_check'] +=1

def PutFlagService(team,serv):
    team_port = team['start_port']+serv['port']
    flagid = idgen(random.choice(range(7,12)))
    flag = GenFlag()
    if serv['checker'].endswith(".py"):
        res = sp.Popen(["python3",serv['checker'],
                        "put",team['ip']+":"+str(team_port),flagid,flag],stdout=sp.PIPE,stderr=sp.PIPE)
    else:
        res = sp.Popen([serv['checker'],"put",team['ip']+":"+str(team_port),flagid,flag],stdout=sp.PIPE,stderr=sp.PIPE)
    r = res.communicate()
    code = res.returncode
    return code,r[0],r[1],flagid,flag

def PutAllFlags():
    for serv in services:
        for t in teams:
            print(f"[CHECKER] Puting flag to team {t} service {serv}")
            code,stdout,stderr,flagid,flag = PutFlagService(t,serv)
            with scoreboard_mutex:
                scoreboard[t['name']][serv['name']]['last_code_put']=code
                scoreboard[t['name']][serv['name']]['last_mes_put']=(stdout.decode(),stderr.decode())
                scoreboard[t['name']][serv['name']]['total_put'] +=1
                if code == 0:
                    scoreboard[t['name']][serv['name']]['success_put'] +=1
                    p = (stdout.decode().strip(),flag)
                    scoreboard[t['name']][serv['name']]['last_put_flag'].append(p)
                    if len(scoreboard[t['name']][serv['name']]['last_put_flag']) > params['flag_lifetime']:
                        scoreboard[t['name']][serv['name']]['last_put_flag'] = \
                            scoreboard[t['name']][serv['name']]['last_put_flag'][-params['flag_lifetime']:]

def GetFlagService(team,serv,flagid,flag):
    team_port = team['start_port']+serv['port']
    if serv['checker'].endswith(".py"):
        res = sp.Popen(["python3",serv['checker'],"get",team['ip']+":"+str(team_port),flagid,flag],stdout=sp.PIPE,stderr=sp.PIPE)
    else:
        res = sp.Popen([serv['checker'],"get",team['ip']+":"+str(team_port),flagid,flag],stdout=sp.PIPE,stderr=sp.PIPE)
    r = res.communicate()
    code = res.returncode
    return code,r[0],r[1]

def GetAllFlags():
    for serv in services:
        for t in teams:
            print(f"[CHECKER] Geting flag from team {t} service {serv}")
            if len(scoreboard[t['name']][serv['name']]['last_put_flag']) == 0:
                print(f"[CHECKER] No flags to get for team {t} at {serv}")
                continue
            flagid,flag = scoreboard[t['name']][serv['name']]['last_put_flag'][-1]
            code,stdout,stderr = GetFlagService(t,serv,flagid,flag)
            with scoreboard_mutex:
                scoreboard[t['name']][serv['name']]['last_code_get']=code
                scoreboard[t['name']][serv['name']]['last_mes_get']=(stdout.decode(),stderr.decode())
                scoreboard[t['name']][serv['name']]['total_get'] +=1
                if code == 0:
                    scoreboard[t['name']][serv['name']]['success_get'] +=1
                    scoreboard[t['name']][serv['name']]['total_flags_stored'] +=1
                else:
                    scoreboard[t['name']][serv['name']]['total_flags_loss'] +=1

def ReceiveHackedFlags(team_name,flag):
    if not team_name in scoreboard:
        return 0,"No such team"
    for t in scoreboard:
        if t == team_name:
            continue
        for s in scoreboard[t]:
            for f in scoreboard[t][s]['last_put_flag']:
                cur_flag = f[1]
                if flag == cur_flag:
                    with scoreboard_mutex:
                        p=(t,s,flag)
                        if p in scoreboard[team_name][s]['this_passed_flags']:
                            return 0,"Already passed"
                        scoreboard[team_name][s]['this_passed_flags'].append(p)

                        fset=set([])
                        for f in scoreboard[team_name][s]['this_passed_flags']:
                            fset.add(tuple(f))
                        for f in scoreboard[team_name][s]['this_passed_flags']:
                            found=0
                            for lpf in scoreboard[f[0]][f[1]]['last_put_flag']:
                                if lpf[1] == f[2]:
                                    found=1
                                    break
                            if found == 0:
                                fset.remove(p)
                        scoreboard[team_name][s]['this_passed_flags'] = list(fset)

                        scoreboard[team_name][s]['total_flags_hacked'] +=1
                        scoreboard[t][s]['total_flags_stealed'] +=1
                        return 1,f"Accepted +1 from {t}"
    return 0,"No such flag"

def HowSortTeamsKey(team):
    attack = 0
    protect = 0
    for serv in scoreboard[team]:
        attack += scoreboard[team][serv]['total_flags_hacked']
        protect += scoreboard[team][serv]['total_flags_stored'] -\
                                scoreboard[team][serv]['total_flags_stealed']
    return attack + protect
def ShowScoreboard(fname=""):
    team_order = list(scoreboard.keys())
    team_order.sort(key=HowSortTeamsKey,reverse=True)
    table = []
    for team_name in team_order:
        if len(table)==0:
            caption = ["team\\service"]
            for serv in scoreboard[team_name]:
                caption.append(serv)
            caption.append("Attack")
            caption.append("Protection")
            caption.append("Score")
            table.append(caption)
        line = [team_name]
        attack = 0
        protect = 0
        for serv in scoreboard[team_name]:
            attack += scoreboard[team_name][serv]['total_flags_hacked']
            protect += scoreboard[team_name][serv]['total_flags_stored'] -\
                                scoreboard[team_name][serv]['total_flags_stealed']
            line.append(f"{scoreboard[team_name][serv]['total_flags_hacked']}/{scoreboard[team_name][serv]['total_flags_stored'] - scoreboard[team_name][serv]['total_flags_stealed']}")
        line.append(attack)
        line.append(protect)
        line.append(attack+protect)
        table.append(line)
    sb = tabulate.tabulate(table[1:], headers=table[0], tablefmt="grid")
    if fname=="":
        print(sb)
    else:
        open(fname,"w").write(sb)

def StartFlagReceive():
    def HandleConnect(s):
        inp_set = [s]
        team_name = None
        work=1
        while work:
            inputready, outputready, exceptready = select.select(inp_set, [], [],60)
            found_flag = 0
            for x in inputready:
                if x == s:
                    data = s.recv(1024)
                    if b"exit" in data:
                        break
                    if len(data)==0:
                        work=0
                        break;
                    result=b""
                    for flag in data.decode().split("\n"):
                        if not team_name:
                            team_name = flag.strip()
                            continue
                        flag = flag.strip()
                        if len(flag)==0:
                            continue
                        found_flag=1
                        status,mes = ReceiveHackedFlags(team_name,flag.strip())
                        result += flag.encode()+b" "+mes.encode()+b"\n"
                        print(f"[FLAGRCV] Team {team_name} {mes} { flag.encode()}")
                    s.send(result)
            StoreScoreboard()
            if found_flag==0:
                break

        s.close()
    SERVER_ADDRESS = ('0.0.0.0', params['flag_port'])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket .setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    server_socket.bind(SERVER_ADDRESS)
    server_socket.listen(10)
    while True:
        connection, address = server_socket.accept()
        print("[FLAGRCV]new connection from {address}".format(address=address))
        t=threading.Thread(target=HandleConnect,args=(connection,))
        t.start()

def ViewScoreboard():
    while 1:
    #    try:
            ShowScoreboard(params['scoreboard'])
            time.sleep(5)
     #   except Exception:
 #           print(traceback.format_exc())
#

t=threading.Thread(target=StartFlagReceive)
t.daemon=True
t.start()
t2=threading.Thread(target=ViewScoreboard)
t2.daemon=True
t2.start()


if sys.argv[1] == "now":
    NUM_RUN = 10000
    for i in range(NUM_RUN):
        print(f"Round {i}")
        t1 = datetime.datetime.now()
        CheckAllService()
        PutAllFlags()
        GetAllFlags()
        StoreScoreboard()
        ShowScoreboard()
        t2 = datetime.datetime.now()
        diff = params['round_time'] - ((t2-t1).total_seconds())
        if diff>0:
            print(f"Sleeping {diff}")
            time.sleep(diff)
