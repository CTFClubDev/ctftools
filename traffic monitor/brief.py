import re

def default(requests):
    s=b""
    for req in requests:
        res = re.findall(b"^(\\w+)",req['content'])
        if len(res)>0:
            s+=res[0]+b" "
    return s.decode()
