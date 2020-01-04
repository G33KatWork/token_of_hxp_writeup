#!/usr/bin/env python2
import struct, sys, json, pprint
j=json.loads(open(sys.argv[1]).read())

outfile = open(sys.argv[2], "wb")

remaining = 0
addr = None
chunk = ""
for i in j:
    i = i["_source"]["layers"]["Setup Data"]
    r = int(i["usb.setup.bRequest"], 10)
    #a = eval(i["usb.setup.wIndex"])
    a = int(i["usb.setup.wIndex"], 10)
    #b = eval(i["usb.setup.wValue"])

    if i["usb.setup.wValue"][2:].lstrip('0') == '':
        b = 0
    else:
        b = int(i["usb.setup.wValue"][2:].lstrip('0'), 16)
    
    length = int(i["usb.setup.wLength"], 10)
    if r == 2:
        assert not any((length,a,b))
        outfile.seek(0)
        outfile.write("\xff" * 0x1980)
        continue
    if r == 1:
        assert not length
        assert remaining == 0
        addr = a
        remaining = b
        chunk = ""
        assert remaining == 64
        continue
    if r == 3:
        assert not length
        assert remaining >= 4
        chunk += struct.pack("HH", b, a)
        remaining -= 4
        if remaining == 0:
            outfile.seek(addr)
            outfile.write(chunk)
        continue
    assert False
