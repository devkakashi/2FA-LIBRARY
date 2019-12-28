#!/usr/bin/python3

#

import random
import base64
import time
import hashlib
import hmac

#

def newcode(seed=None):

    locktime, timepattern = (int(time.time()) // 30, bytearray())

    if not len(str(seed)) >= 16:
    
        return [None, False]

    while locktime != 0:

        timepattern.append(locktime & 0xFF)
        locktime >>= 8
    
    timepattern = bytes(bytearray(reversed(timepattern)).rjust(8, b'\0'))

    if len(seed) % 8:

        seed = base64.b32decode('{0}{1}'.format(seed, '=' * (8 - len(seed) % 8)))
    
    hash = hmac.new(seed.encode(), timepattern, hashlib.sha1)
    hash = bytearray(hash.digest())

    offset = hash[-1] & 0xf

    data = ((hash[offset]) << 24 | (hash[offset+1] & 0xff) << 16 | (hash[offset+2] & 0xff) << 8 | (hash[offset + 3] & 0xff))
    data = str(data % 10 ** 6)

    while len(data) < 6:
        data = '0' + data

    return [int(data), True]

def newseed(length=16):

    if length < 16:

        length = length + (16 - length)

    return ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(length))

def verify(seed=None, code=None):

    if seed == None or code == None: 
        
        return False

    return newcode(seed)[0] == int(code)
