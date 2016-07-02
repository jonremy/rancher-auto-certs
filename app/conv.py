#!/usr/bin/python

import sys, json, base64, binascii, subprocess, os

if len(sys.argv) != 3:
    print("Convert your account key from private_key.json JWK format to PEM")
    print("Usage: python3 conv.py json_input_file out_file")
    exit()

with open(sys.argv[1]) as fp:
    pkey=json.load(fp)

def enc(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding:
      data += b'='* missing_padding
    return '0x'+binascii.hexlify(base64.b64decode(data,b'-_')).decode("utf-8").upper()

for k,v in pkey.items():
    if k == 'kty': continue
    pkey[k] = enc(v.encode())

asn1 = "asn1=SEQUENCE:private_key\n[private_key]\nversion=INTEGER:0"
asn1 += "\nn=INTEGER:{}".format(pkey[u'n'])
asn1 += "\ne=INTEGER:{}".format(pkey[u'e'])
asn1 += "\nd=INTEGER:{}".format(pkey[u'd'])
asn1 += "\np=INTEGER:{}".format(pkey[u'p'])
asn1 += "\nq=INTEGER:{}".format(pkey[u'q'])
asn1 += "\ndp=INTEGER:{}".format(pkey[u'dp'])
asn1 += "\ndq=INTEGER:{}".format(pkey[u'dq'])
asn1 += "\nqi=INTEGER:{}".format(pkey[u'qi'])


def openssl(args):
    proc = subprocess.Popen(["openssl"] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err.decode("utf-8")))
    return out

with open(sys.argv[2]+'.asn1', 'w') as f:
    f.write(asn1)

openssl(["asn1parse", "-noout", "-out", sys.argv[2]+'.der', "-genconf", sys.argv[2]+'.asn1'])
os.remove(sys.argv[2]+'.asn1')
openssl(["rsa", "-in", sys.argv[2]+'.der', "-inform", "der", "-out", sys.argv[2]])
os.remove(sys.argv[2]+'.der')
