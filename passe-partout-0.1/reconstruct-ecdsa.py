#!/usr/bin/env python

# pip install --user pycryptodome

from Crypto.PublicKey import ECC
import sys

if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s <ecdsa->priv_key value>\n" % sys.argv[0])
    sys.exit(-1)

# P-256 is known as prime256v1 in OpenSSL
# https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations#EC_Private_Key_File_Formats

o = ECC.construct(curve='P-256', d=int(sys.argv[1]))
print o.export_key(format="PEM")
