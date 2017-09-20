# -*- coding: utf-8 -*-
"""
Created on Wed Sep 20 13:04:59 2017

@author: ubuntu
"""
###GIVEN CODE#####
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Util import number
import datetime
import hashlib

# Utility to make a cryptography.x509 RSA key object from p and q
def make_privkey(p, q, e=65537):
    n = p*q
    d = number.inverse(e, (p-1)*(q-1))
    iqmp = rsa.rsa_crt_iqmp(p, q)
    dmp1 = rsa.rsa_crt_dmp1(e, p)
    dmq1 = rsa.rsa_crt_dmq1(e, q)
    pub = rsa.RSAPublicNumbers(e, n)
    priv = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
    pubkey = pub.public_key(default_backend())
    privkey = priv.private_key(default_backend())
    return privkey, pubkey

# The ECE422 CA Key! Your cert must be signed with this.
ECE422_CA_KEY, _ = make_privkey(10079837932680313890725674772329055312250162830693868271013434682662268814922750963675856567706681171296108872827833356591812054395386958035290562247234129L,13163651464911583997026492881858274788486668578223035498305816909362511746924643587136062739021191348507041268931762911905682994080218247441199975205717651L)

# Skeleton for building a certificate. We will require the following:
# - COMMON_NAME matches your netid.
# - COUNTRY_NAME must be US
# - STATE_OR_PROVINCE_NAME must be Illinois
# - issuer COMMON_NAME must be ece422
# - 'not_valid_before' date must must be September 6
# - 'not_valid_after'  date must must be September 20
# Other fields (such as pseudonym) can be whatever you want, we won't check them
def make_cert(netid, pubkey, pseudo, ca_key = ECE422_CA_KEY, serial=x509.random_serial_number()):
    builder = x509.CertificateBuilder()
    builder = builder.not_valid_before(datetime.datetime(2017, 9, 6))
    builder = builder.not_valid_after (datetime.datetime(2017, 9, 20))
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, unicode(netid)),
        x509.NameAttribute(NameOID.PSEUDONYM, pseudo),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Illinois'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'ece422'),
]))
    builder = builder.serial_number(serial)
    builder = builder.public_key(pubkey)
    cert = builder.sign(private_key=ECE422_CA_KEY, algorithm=hashes.MD5(), backend=default_backend())
    return cert

### End Given CODE ###

import binascii
import numpy as np
import sys
from pymd5 import md5, padding

p = number.getPrime(1024)
q = number.getPrime(1024)
privkey, pubkey = make_privkey(p, q)
init_cert = make_cert("kjhand2", pubkey, u'unused123456789asdfgqwertasd')
prefix = init_cert.tbs_certificate_bytes[:192] # this is the prefix

with open("prefix_file.txt", "w") as f:
    f.write(prefix)

assert (len(sys.argv) > 1),  "No Collision Provided"



