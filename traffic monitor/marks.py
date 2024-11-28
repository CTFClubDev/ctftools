import re
def handler1(payload):
    if b"/bin/sh" in payload:
        return 1
    return 0

def handler2(payload):
    res = re.findall(b"HACK",payload)
    return len(res),f"HACK({len(res)})",f"rgb(256,{10 * len(res) },0)"

marks = [
    #dict(name="flag",proto="tcp",port="8081",color="#ff0000",type="regex",regex=b"CTF{[0-9A-Za-z]{32}}" ),
    dict(name="HACK",proto="tcp",port="8081",color="#ff0000",type="regex",regex=b"HACK" ),
    dict(name="attack1",proto="tcp",port="8081",color="#00ff00",type="call",handler=handler1),
    dict(name="hack2",proto="tcp",port="8081",color="#00ff00",type="call",handler=handler2)
]
