from scapy.all import *
from flask import *
from flask_basicauth import BasicAuth
from netfilterqueue import NetfilterQueue
import datetime,os,time,threading,re,traceback,base64
from importlib import reload

import sys
parser = argparse.ArgumentParser(
                    prog='traf block',
                    description='block attacks')
parser.add_argument('-m', '--mode',default="intercept",choices=['monitor', 'intercept'])
parser.add_argument('-p', '--port',default="5555",type=int)
parser.add_argument('-c', '--credentials',default="qwe",type=str)
args = parser.parse_args()
SHOW_MINUTES = 30
ENABLE_BLOCK = True
NFQUEUENUM = 31337
COLLECT_PAYLOAD = False
COLLECT_PAYLOAD_LAST_TIME = 1
TIME_OFFSET = 3
################ MARKS      ###################
import marks
current_marks = {}
def LoadMarks():
    global current_marks,marks
    mcurrent_marks = {}
    marks = reload(marks)
    all_marks = marks.marks
    for m in all_marks:
        pair = (m['proto'],int(m['port']))
        if not pair in mcurrent_marks:
            mcurrent_marks[pair] = []
        el={}
        el['port'] = int(m['port'])
        el['proto'] = m['proto']
        el['name'] = m['name']
        el['type'] = m['type']
        el['color'] = m['color']
        if m['type'] == 'regex':
            el['regex'] = m['regex']
        elif m['type'] == 'call':
            el['handler'] = m['handler']
        mcurrent_marks[pair].append(el)
    current_marks=mcurrent_marks
marks_m1 = 0
def ReloaderMarks():
    global marks_m1
    m1 = os.path.getmtime("marks.py")
    if marks_m1 == 0 or m1 > marks_m1:
        marks_m1 = m1
        print("Reloading marks")
        try:
            LoadMarks()
        except:
            traceback.print_exc()
        print("Reloaded marks")
ReloaderMarks()
################ SIGNATURES ###################
import signatures
SIGNATURES = {}
def LoadSignatures():
    global signatures,SIGNATURES
    signatures = reload(signatures)
    sigs = signatures.signatures
    mSIGNATURES = {}
    for n in sigs:
        s=sigs[n]
        pair = (s['proto'],int(s['port']))
        if not pair in mSIGNATURES:
            mSIGNATURES[pair] = []
        el={}
        el['port'] = int(s['port'])
        el['proto'] = s['proto']
        el['dir'] = s['dir']
        el['name'] = s['name']
        el['type'] = s['type']
        if s['type'] == 'regex':
            el['regex'] = s['regex']
        elif s['type'] == 'call':
            el['handler'] = s['handler']
        mSIGNATURES[pair].append(el)
    SIGNATURES=mSIGNATURES

def ReloaderSignature():
    m1 = os.path.getmtime("signatures.py")
    while 1:
        m2 = os.path.getmtime("signatures.py")
        if m2 > m1:
            print("Reloading signatures",m1,m2)
            m1 = m2
            try:
                LoadSignatures()
            except:
                traceback.print_exc()
            print("Reloaded signatures")
        time.sleep(10)
if ENABLE_BLOCK:
    t = threading.Thread(target=ReloaderSignature)
    t.daemon = True
    t.start()

def SaveSignatures():
    f = open(fname,"w+")
    f.write(signatures)
    f.close()
if ENABLE_BLOCK:
    LoadSignatures()
################ SERVICES ###################
import services
socket_to_payload = {}
current_services = {}
p2s={}
last_load = 0
def LoadServices():
    global current_services,last_load,services
    m1 = os.path.getmtime("services.py")
    if last_load == 0 or last_load < m1:
        print("Reloading services")
        services = reload(services)
        current_services = {}
        for serv in services.services:
            current_services[serv['name']] = serv
            p2s[(serv['proto'].lower(),serv['port'])] = serv
        last_load = m1
        print("Reloaded services")

def GetPort(name):
    if name in current_services:
        return current_services[name]['port']
def GetBriefHandler(name):
    if name in current_services:
        if 'brief' in current_services[name]:
            return current_services[name]['brief']
LoadServices()
def write(pkt,port):
    tm = datetime.datetime.now()
    tm_str = tm.strftime(f"pcaps/%y%m%d_%H___{port}.pcap")
    wrpcap(tm_str, pkt, append=True)
################ INTERCEPT ###################
def modify(pak):
    pkt = IP(pak.get_payload())
    dropped = False
    if pkt.haslayer(TCP):
        srcip = pkt[IP].src
        dstip = pkt[IP].dst
        srcport = pkt[TCP].sport
        dstport = pkt[TCP].dport
        pld = pkt[TCP].payload
        print(f"{srcip}:{srcport}->{dstip}:{dstport} {pld}")
        pair1 = ('tcp',srcport)
        pair2 = ('tcp',dstport)
        cur_direction, service_port = 0,0
        if pair1 in p2s:
            cur_direction = "OUT"
            service_port = srcport
        if pair2 in p2s:
            cur_direction = "IN"
            service_port = dstport
        js = pkt[TCP].json()
        if len(pkt[TCP].payload) >0 :
            load =  pkt[TCP].payload.load
            if COLLECT_PAYLOAD:
                tm = pkt[TCP].time
                conn = (srcip,srcport,dstip,dstport)
                if not conn in socket_to_payload:
                    socket_to_payload[conn] = dict(last_time=0,cont=b'')
                if socket_to_payload[conn]['last_time'] ==0 or \
                    tm - socket_to_payload[conn]['last_time'] < COLLECT_PAYLOAD_LAST_TIME:
                    socket_to_payload[conn]['cont'] += load
                    #print(socket_to_payload[conn]['cont'].decode())
            if ENABLE_BLOCK:
                pair = ('tcp',service_port)
                if pair in SIGNATURES:
                    for sig in SIGNATURES[pair]:
                        if cur_direction == sig['dir']:
                            if sig['type'] == 'regex':
                                res = re.findall(sig['regex'],load)
                                if len(res) !=0:
                                    pak.drop()
                                    dropped =True
                            elif sig['type'] == 'call':
                                res = sig['handler'](load)
                                if res !=0:
                                    pak.drop()
                                    dropped =True
                            if dropped:
                                pkt[IP].options.append(IPOption(f"dropped {sig['name']}".encode()))

                        if dropped:
                            print(f"Signature {sig['name']} acted")
    write(pkt,service_port)
    if not dropped:
        pak.accept()
################ FLASK ###################
def GetPackets(from_time,to_time,port):
    cur_time = from_time
    fls = []
    while cur_time < to_time:
        fls.append(cur_time.strftime(f"pcaps/%y%m%d_%H___{port}.pcap"))
        cur_time += datetime.timedelta(hours=1)
    fls.append(cur_time.strftime(f"pcaps/%y%m%d_%H___{port}.pcap"))
    packs = []
    for fff in fls:
        if os.path.isfile(fff):
            packets = rdpcap(fff)
            packs.append(packets)
    return packs
app = Flask(__name__)
app.config['BASIC_AUTH_USERNAME'] = 'admin'
app.config['BASIC_AUTH_PASSWORD'] = args.credentials
basic_auth = BasicAuth(app)
print(dir(basic_auth))
@app.route('/')
@basic_auth.required
def index():
    LoadServices()
    ReloaderMarks()
    vals = request.values
    tcp_connections = {}
    if 'srv' in vals:
        srv_name = vals['srv']
        port = GetPort(srv_name)
        brief_handler = GetBriefHandler(srv_name)
        SHOW_MINUTES_0 = SHOW_MINUTES
        if 'show_minutes' in vals:
            SHOW_MINUTES_0 = int(vals['show_minutes'])
        current_time = datetime.datetime.now()
        if 'from_time' in vals and 'date' in vals and len(vals['date'])>0 and len(vals['from_time'])>0:
            from_time = vals['from_time']
            res = re.findall(r'(\d+):(\d+)',from_time)
            if len(res)>0:
                new_h = int(res[0][0])
                new_m = int(res[0][1])
            current_time = datetime.strptime("%y%m%d_%H",vals['date'])
            current_time = current_time.replace(hour=new_h,minute=new_m)
            current_time -= datetime.timedelta(hours=TIME_OFFSET)
            time_from0=current_time - datetime.timedelta(minutes=SHOW_MINUTES_0)
            time_to0=current_time
        elif 'date' in vals  and len(vals['date'])>0:
            current_time = datetime.strptime("%y%m%d_%H",vals['date'])
            current_time = current_time.replace(hour=current_time.hour,minute=current_time.minute)
            current_time -= datetime.timedelta(hours=TIME_OFFSET)
            time_from0=current_time - datetime.timedelta(minutes=SHOW_MINUTES_0)
            time_to0=current_time
        elif 'from_time' in vals and len(vals['from_time'])>0:
            from_time = vals['from_time']
            res = re.findall(r'(\d+):(\d+)',from_time)
            if len(res)>0:
                new_h = int(res[0][0])
                new_m = int(res[0][1])
            current_time2 = current_time.replace(hour=new_h,minute=new_m)
            if (current_time2 - datetime.timedelta(hours=TIME_OFFSET)).date() != current_time.date():
                current_time2 += datetime.timedelta(days=1)
            current_time = current_time2 - datetime.timedelta(hours=TIME_OFFSET)
            time_from0 = current_time - datetime.timedelta(minutes=SHOW_MINUTES_0)
            time_to0 = current_time
        else:
            time_from0 = current_time - datetime.timedelta(minutes=SHOW_MINUTES_0)
            time_to0 = current_time
        time_from = (time_from0-datetime.datetime(1970,1,1)).total_seconds()
        time_to = (time_to0-datetime.datetime(1970,1,1)).total_seconds()
        packs = GetPackets(time_from0,time_to0,port)
        filter_regex = ''
        if 'filter_regex' in request.values:
            filter_regex = request.values['filter_regex']

        for packets in packs:
            for pkt in packets:
                if not pkt.haslayer(TCP):
                    continue
                tm = pkt.time
                if not time_from <= tm <= time_to:
                    continue
                if not len(pkt[TCP].payload) >0:
                    continue
                if pkt['TCP'].sport == port:
                    cport = pkt['TCP'].dport
                    direction = ">"
                elif pkt['TCP'].dport == port:
                    cport = pkt['TCP'].sport
                    direction = "<"
                else:
                    continue
                if not cport in tcp_connections:
                    tcp_connections[cport] = dict(requests=[],start_time = tm,cport=cport,requests_count=0,mark=[])
                tcp_connections[cport]['requests'].append(dict(content=pkt[TCP].payload.load,direction=direction))
                tcp_connections[cport]['requests_count']+=1
                dt_object = datetime.datetime.utcfromtimestamp(int(tm))+ datetime.timedelta(hours=TIME_OFFSET)
                formatted_time = dt_object.strftime('%Y-%m-%d %H:%M:%S')
                tcp_connections[cport]['end_time'] = formatted_time

        marks=[]
        if ('tcp',port) in current_marks:
            marks = current_marks[('tcp',port)]

        for cport in tcp_connections:
            if not 'brief' in tcp_connections[cport]:
                if brief_handler:
                    tcp_connections[cport]['brief'] = brief_handler(tcp_connections[cport]['requests'])
                else:
                    pak = tcp_connections[cport]['requests'][0]['content']
                    tcp_connections[cport]['brief'] = repr(pak[0:64])[2:-1]

        if len(filter_regex) > 0:
            tcp_connections2=[]
            for cport in tcp_connections:
                content = tcp_connections[cport]
                total_s = b''
                for req in content['requests']:
                    total_s+=req['content']
                res = re.findall(filter_regex.encode(),total_s,flags=re.DOTALL)
                if len(res)>0:
                    content['brief'] += "|" +repr(res)
                    tcp_connections2.append(content)
        else:
            tcp_connections2 = list(tcp_connections.values())

        if len(marks) >0:
            for content in tcp_connections2:
                total_s = b''
                for req in content['requests']:
                    total_s+=req['content']
                for m in marks:
                    if m['type'] == 'regex':
                        res = re.findall(m['regex'],total_s,flags=re.DOTALL)
                        if len(res)>0:
                            content['mark'].append(dict(name=m['name'],color=m['color']))
                    elif m['type'] == 'call':
                        try:
                            res = m['handler'](total_s)
                            if type(res) == type((1,1)):
                                if res[0]:
                                    content['mark'].append(dict(name=res[1],color=res[2]))
                            else:
                                if res:
                                    content['mark'].append(dict(name=m['name'],color=m['color']))
                        except:
                            traceback.print_exc()


        for conn in tcp_connections2:
            for i in range(len(conn['requests'])):
                conn['requests'][i]['content'] = base64.b64encode(conn['requests'][i]['content'])

        tcp_connections2.sort(key=lambda x: x['end_time'],reverse=True)
        time_from0 = time_from0 + datetime.timedelta(hours=TIME_OFFSET)
        time_to0 = time_to0 + datetime.timedelta(hours=TIME_OFFSET)
        return render_template("index.html",services=current_services,tcp_connections=tcp_connections2,
                            time_from=time_from0.strftime("%H:%M"),
                            time_to=time_to0.strftime("%H:%M"))
    return render_template("index.html",
                           services=current_services,
                           tcp_connections=[],
                            time_from="",
                            time_to="")

def StartFlask():
    print("Starting")
    app.run(host="0.0.0.0",port=args.port,threaded=True,debug=False)

t = threading.Thread(target=StartFlask)
t.daemon=True
t.start()
################ NETFILTER ###################
if args.mode == 'monitor':
    print("Monitor mode")
    while 1:
        pass
elif args.mode == 'intercept':
    print("Intercept mode")
    nfqueue = NetfilterQueue()
    nfqueue.bind(NFQUEUENUM, modify)
    try:
        print ("[*] waiting for data")
        nfqueue.run()
    except KeyboardInterrupt:
        nfqueue.unbind()
    nfqueue.unbind()
