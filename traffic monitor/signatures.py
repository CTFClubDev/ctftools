import re
def handler1(payload):
    if re.findall(b'H@CK',payload):
        return 1
    return 0

signatures = dict(
    test_sig=dict(name="test_sig",proto="tcp",port="8081",dir="OUT",type="regex",regex=b"H4CK" ),
    test_sig2=dict(name="test_sig2",proto="tcp",port="8081",dir="OUT",type="call",handler=handler1)
)
