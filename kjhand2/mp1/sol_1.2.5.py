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
import struct
import math
from fractions import gcd

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
padding = u'0000000000000000000000000000000000000000000000000000000000000000'
### End Given CODE ###
#output of chinese remainder theorem 
def getCRT(b1,b2,p1,p2):
    Num = p1 * p2
    inv1 = number.inverse(p2,p1)
    inv2 = number.inverse(p1,p2)
    return -(b1 * inv1 * p2 + b2 * inv2 * p1) %Num
def isPrime(n):
    n = abs(int(n))
    if n < 2:
        return False
    if n ==2:
        return True
    if not n & 1:
        return False

#    for x in range(3,int(n.sqrt())+1,2):
#            if n % x ==0:
#                return False
    return True
'''
def isPrime(a):
    return all(a % i for i in xrange(2, a))
'''
def getCoprimes(e=5537):
    bitSize = 512
    p1, p2 = -1, -1
    while p1 == p2:
        p1 = number.getStrongPrime(bitSize, e)
        p2 = number.getStrongPrime(bitSize, e)
    assert(gcd(e, p1-1) ==1)
    assert(gcd(e, p2-1) == 1)
    return p1, p2
e = 65537
import binascii
import numpy as np
import sys
from pymd5 import md5, padding
test = 0

while test ==0:
    p = number.getPrime(1024)
    q = number.getPrime(1024)
#    print (p*q).bit_length()
    if (p*q).bit_length() == 2047:
        test =1
print (p*q).bit_length()
privkey, pubkey = make_privkey(p, q)
init_cert = make_cert("kjhand2", pubkey,u'0000000000000000000000000000000000000000000000000000000000000000')
prefix = init_cert.tbs_certificate_bytes[:256] # this is the prefix
#assert ((len(prefix)) % 64 ==0),"length of prefix is not 64"
with open("prefix_file", "wb") as f:
    f.write(binascii.hexlify(bytearray(prefix)))

#assert (len(sys.argv) > 1),  "No Collision Provided"

#in and out 
b1File = open(sys.argv[1],"rb")
b2File = open(sys.argv[2],"rb")
b1cont = b1File.read()
b2cont = b2File.read()
print len(b1cont)
print len(b2cont)
#b1bin = b1cont.decode('hex')
#b2bin = b2cont.decode('hex')
#b1cont = b1cont[2:]
#b2cont = b2cont[2:]
print b1cont 
print b2cont
b1 = b1cont[512:]
b2 = b2cont[512:]
b1 = int(binascii.hexlify(bytearray(b1cont)),16)
b2 = int(binascii.hexlify(bytearray(b2cont)),16)

 
#b1 = int(b1File.read(),16)
#b2 = int(b2File.read(),16)
print b1.bit_length()
print b2.bit_length()
b1 = b1<<1024
b2 = b2<<1024
#generate random primes p1 and p2 of approximately 512 bits, such that e is coprime to p1 − 1 and p2 − 1;
coprime = 0
while coprime == 0:
#    p1 = number.getPrime(512)
#    p2 = number.getPrime(512)
    p1,p2 = getCoprimes(e)
    if e % (p1-1) != 0 and e % (p2-1) != 0:
        coprime = 1

test = 0
while test == 0:
    b0 = getCRT(b1=b1,b2=b2,p1=p1,p2=p2)
    if gcd(b1+b0,p1) == p1 and gcd(b2+b0,p2) == p2 and (b1+b0) % p1 ==0 and (b2+b0) % p2 ==0:
        print "b0 thing is right"
        test = 1
    else:
        print"shit doesnt work"
        test =1
b=0
k=0
while k != -1:
    b = b0 + k*p1*p2
#please dont hate me.... i didnt want to organize everything again
    if b >= 2**1024:
        coprime = 0
        while coprime == 0:
#            p1 = number.getPrime(512)
#            p2 = number.getPrime(512)
            p1,p2 = getCoprimes(e)            
            if e % (p1-1) != 0 and e % (p2-1) != 0:
                coprime = 1

        test = 0
        while test == 0:
            b0 = getCRT(b1=b1,b2=b2,p1=p1,p2=p2)
            if gcd(b1+b0,p1) == p1 and gcd(b2+b0,p2) == p2 and (b1+b0) % p1 ==0 and (b2+b0) % p2 ==0:
                print "b0 thing is right"
                test = 1
            else:
                print"shit doesnt work"
                test =1
    q1 = int((b1*2**1024 + b)/p1)
    q2 = int((b2*2**1024 + b)/p2)
    if e % (q1-1) != 0 and e % (q2-1) != 0:
#    if e % (q1-1) != 0 and e % (q2-1) != 0:
        break
    k = k+1
    if k > 10000:
        print "shit went wrong"
        break

    
n1 = b1*2**1024 + b
n2 = b2*2**1024 + b
if gcd(q1-1,e) != 1:
    print "gcd(q1-1,e)"
if gcd(q2-1,e) != 1:
    print "gcd(q2-1,e)"
#print n1
#print n2

ver1 = [2]
# return privkey, pubkey
privkey1, pubkey1 = make_privkey(p1, q1, e)
privkey2, pubkey2 = make_privkey(p2, q2, e)
#make_cert(netid, pubkey, pseudo, ca_key = ECE422_CA_KEY, serial=x509.random_serial_number())

cert1 = make_cert("kjhand2",pubkey1,u'0000000000000000000000000000000000000000000000000000000000000000')
cert2 = make_cert("kjhand2",pubkey2,u'0000000000000000000000000000000000000000000000000000000000000000')

