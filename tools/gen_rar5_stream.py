# SPDX-License-Identifier: GPL-3.0-or-later
import random, sys
# Test-only RAR5 stream generator: fixed tables, literals + short matches.
class BW:
    def __init__(s): s.b=bytearray(); s.acc=0; s.n=0
    def put(s,v,n):
        for i in range(n-1,-1,-1):
            s.acc=(s.acc<<1)|((v>>i)&1); s.n+=1
            if s.n==8: s.b.append(s.acc); s.acc=0; s.n=0
    def finish(s):
        bits = s.n if s.n else 8
        if s.n: s.b.append(s.acc<<(8-s.n)); 
        return bytes(s.b), bits
def canon(lens):
    order=sorted([i for i,l in enumerate(lens) if l],key=lambda i:(lens[i],i))
    codes={}; code=0; prev=0
    for i in order:
        code <<= (lens[i]-prev); prev=lens[i]; codes[i]=code; code+=1
    return codes
MAIN=[0]*306
for i in range(256): MAIN[i]=9
for i in range(262,270): MAIN[i]=9
DIST=[4]*16+[0]*48; LOW=[4]*16; REP=[0]*44
ALL=MAIN+DIST+LOW+REP
mc,dc,lc=canon(MAIN),canon(DIST),canon(LOW)
def tables(w):
    for i in range(20): w.put(5,4)   # level code: 20 symbols, 5 bits
    for l in ALL: w.put(l,5)          # level symbol l encodes length l
def dist_enc(w,d):
    v=d-1
    for slot in range(16):
        if slot<4:
            if v==slot: w.put(dc[slot],4); return
            continue
        extra=slot//2-1; base=(2|(slot&1))<<extra
        if base<=v<base+(1<<extra):
            w.put(dc[slot],4); r=v-base
            if extra>=4:
                if extra>4: w.put(r>>4,extra-4)
                w.put(lc[r&15],4)
            else: w.put(r,extra)
            return
    raise Exception(d)
rnd=random.Random(int(sys.argv[2])); total=int(sys.argv[1])
words=[bytes(rnd.choice(b"abcdefghijklmnopqrstuvwxyz ") for _ in range(rnd.randint(2,9))) for _ in range(300)]
data=bytearray()
while len(data)<total: data+=rnd.choice(words)
data=bytes(data[:total])
out=bytearray(); pos=0; blk=0; BLOCK=1<<15
while pos<total:
    w=BW(); has_t = blk%4==0
    if has_t: tables(w)
    end=min(total,pos+BLOCK)
    while pos<end:
        best=(0,0)
        for d in (1,2,3,5,8,13,40,100,200,256):
            if d>pos: break
            l=0
            while l<9 and pos+l<end and data[pos+l]==data[pos+l-d]: l+=1
            if l>best[0]: best=(l,d)
        if best[0]>=2:
            l,d=best; w.put(mc[262+l-2],9); dist_enc(w,d); pos+=l
        else:
            w.put(mc[data[pos]],9); pos+=1
    body,bits=w.finish()
    n=len(body); sb=1 if n<256 else 2 if n<65536 else 3
    last = pos>=total
    flags=(bits-1)|((sb-1)<<3)|(0x40 if last else 0)|(0x80 if has_t else 0)
    szb=n.to_bytes(sb,'little'); chk=0x5a^flags
    for x in szb: chk^=x
    out+=bytes([flags,chk])+szb+body; blk+=1
open(sys.argv[3],'wb').write(out); open(sys.argv[3]+'.plain','wb').write(data)
