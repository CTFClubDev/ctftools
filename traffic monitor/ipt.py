import subprocess,re,sys

QUENENUM=31337
import services
current_services = {}
p2s={}
def LoadServices():
    global current_services
    current_services = {}
    for serv in services.services:
        current_services[serv['name']] = serv
        p2s[(serv['proto'].lower(),serv['port'])] = serv
        serv['in_ip_tables']=0
        serv['lines']=[]
LoadServices()

def ListIptables():
    s = subprocess.Popen("iptables -t raw -L PREROUTING -n",stdout=subprocess.PIPE,shell=True)
    res = s.communicate()
    num_rule = 1
    for line in res[0].decode().split("\n")[2:]:
        cur_num = num_rule
        num_rule+=1
        if not "NFQUEUE" in line:
            continue
        res = re.findall(r'(tcp|udp) (dpt|spt):(\d+) NFQUEUE num (\d+)',line)
        if len(res)==0:
            continue
        proto = res[0][0]
        is_sd = res[0][1]
        port = int(res[0][2])
        nfqn = res[0][3]
        pair = (proto,port)
        if pair in p2s:
            p2s[pair]['in_ip_tables'] = 1
            p2s[pair]['lines'].append(cur_num)

def ListServices():
    for s in current_services:
        print(s,current_services[s])

def RemoveService(name):
    ListIptables()
    if name in current_services:
        current_services[name]['lines'].sort(reverse=True)
        for line_num in current_services[name]['lines']:
            s = subprocess.Popen(f"iptables -t raw -R PREROUTING  {line_num}",stdout=subprocess.PIPE,shell=True)

def AddService(name):
    ListIptables()
    if name in current_services:
        if not current_services[name]['in_ip_tables']:
            port = current_services[name]['port']
            proto = current_services[name]['proto']
            s = subprocess.Popen(f"iptables -t raw -A PREROUTING -p {proto} --dport {port} -j NFQUEUE --queue-num {QUENENUM}",
                                 stdout=subprocess.PIPE,shell=True)
            s = subprocess.Popen(f"iptables -t raw -A PREROUTING -p {proto} --sport {port} -j NFQUEUE --queue-num {QUENENUM}",
                                 stdout=subprocess.PIPE,shell=True)

if len(sys.argv) == 1:
    ListIptables()
    ListServices()
elif len(sys.argv) > 1:
    if sys.argv[1] == "del" or sys.argv[1] == "rm" or sys.argv[1] == "d" or sys.argv[1] == "r":
        if len(sys.argv) == 3:
            RemoveService(sys.argv[2])
        elif len(sys.argv) == 2:
            for name in current_services:
                RemoveService(name)
    elif sys.argv[1] == "add" or sys.argv[1] == "a":
        if len(sys.argv) == 3:
            AddService(sys.argv[2])
        elif len(sys.argv) == 2:
            for name in current_services:
                AddService(name)

