# SPDX-License-Identifier: GPL-3.0-or-later
# Test-only generator of valid RAR 3.x LZ streams with random symbols.
import random, sys, struct
class BW:
    def __init__(s): s.b=bytearray(); s.acc=0; s.n=0
    def put(s,v,n):
        for i in range(n-1,-1,-1):
            s.acc=(s.acc<<1)|((v>>i)&1); s.n+=1
            if s.n==8: s.b.append(s.acc); s.acc=0; s.n=0
    def align(s):
        while s.n: s.put(0,1)
    def done(s):
        if s.n: s.b.append(s.acc<<(8-s.n))
        return bytes(s.b)+b"\0"*16
def canon(lens):
    order=sorted([i for i,l in enumerate(lens) if l],key=lambda i:(lens[i],i))
    codes={}; code=0; prev=0
    for i in order:
        code <<= (lens[i]-prev); prev=lens[i]; codes[i]=code; code+=1
    return codes
LB=[0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,32,40,48,56,64,80,96,112,128,160,192,224]
LBI=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5]
CNT=[4,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,14,0,12]; DB=[];DBI=[];nx=0
for b,c in enumerate(CNT):
    for _ in range(c): DB.append(nx); DBI.append(b); nx+=1<<b
SB=[0,4,8,16,32,64,128,192]; SBI=[2,2,3,4,5,6,6,6]
r=random.Random(int(sys.argv[1])); nfiles=int(sys.argv[2])
prev=[0]*404
LEVEL=[5]*20; lc=canon(LEVEL)
T={}
def tables(w, first):
    global prev
    w.align(); w.put(0,1)
    keep = r.random()<0.5 and not first
    w.put(1 if keep else 0,1)
    if not keep: prev=[0]*404
    # level lengths with the 15-escape: all 5
    for l in LEVEL: w.put(l,4)
    lens=[9]*299+[6]*60+[5]*17+[5]*28
    for _ in range(r.randint(0,3)):
        i=r.randrange(0,256); lens[i]=0
    i=0
    while i<404:
        if i>0 and r.random()<0.1 and lens[i]==lens[i-1]:
            n=1
            while i+n<404 and n<10 and lens[i+n]==lens[i-1]: n+=1
            if n>=3: w.put(lc[16],5); w.put(n-3,3); i+=n; continue
        if lens[i]==0:
            n=1
            while i+n<404 and lens[i+n]==0 and n<10: n+=1
            if n>=3: w.put(lc[18],5); w.put(n-3,3); i+=n; continue
        w.put(lc[(lens[i]-prev[i])&15],5); i+=1
    prev=lens[:]
    lowrep[0]=0; prevlow[0]=0
    T['m']=canon(lens[:299]); T['ml']=lens[:299]; T['d']=canon(lens[299:359]); T['l']=canon(lens[359:376]); T['r']=canon(lens[376:404])
def mput(w,s): w.put(T['m'][s],T['ml'][s])
recent=[None]*4; last=[0]; lowrep=[0]; prevlow=[0]; produced=0
nfdef=[0]
def number(w,v):
    if v<16: w.put(0,2); w.put(v,4)
    elif v<256: w.put(1,2); w.put(v,8)
    elif v<65536: w.put(2,2); w.put(v,16)
    else: w.put(3,2); w.put(v,32)
def filt(w):
    # filter definition with a random (unknown) program
    cw=BW()
    flags=0
    newf = nfdef[0]==0 or r.random()<0.3
    if newf:
        flags|=0x80; num=nfdef[0]+1
    elif r.random()<0.5:
        flags|=0x80; num=r.randint(1,nfdef[0])
    else: num=None
    if r.random()<0.3: flags|=0x40
    if r.random()<0.7 or newf: flags|=0x20
    if r.random()<0.3: flags|=0x10
    if flags&0x80: number(cw,num)
    number(cw,r.choice([0,1,5,100,300,5000]))
    if flags&0x20: number(cw,r.choice([0,3,10,64,200,1000,4000]))
    if flags&0x10:
        m=r.getrandbits(7); cw.put(m,7)
        for i in range(7):
            if m&(1<<i): number(cw,r.getrandbits(8))
    if flags&0x80 and num==nfdef[0]+1:
        size=r.randint(1,40); number(cw,size)
        for _ in range(size): cw.put(r.getrandbits(8),8)
        nfdef[0]+=1
    code=cw.done()[:-16]
    n=len(code)
    mput(w,257)
    if n<=6: w.put(flags|(n-1),8)
    elif n<=262: w.put(flags|6,8); w.put(n-7,8)
    else: w.put(flags|7,8); w.put(n,16)
    for b in code: w.put(b,8)
out=bytearray(); first=True
for f in range(nfiles):
    w=BW(); size=r.randint(100,80000)
    if first: tables(w,True); first=False
    elif r.random()<0.0: pass
    left=size
    while left>0:
        x=r.random()
        if x<0.003: mput(w,256); w.put(1,1); tables(w,False); continue
        if x<0.006: filt(w); continue
        if x<0.5 or produced<2:
            s=r.randrange(256)
            if not T['ml'][s]: continue
            mput(w,s); left-=1; produced+=1; continue
        if x<0.55:
            if last[0]==0 or recent[0] is None or recent[0]>produced: continue
            mput(w,258); left-=last[0]; produced+=last[0]; continue
        if x<0.65:
            i=r.randint(0,3); d=recent[i]
            if d is None or d>produced: continue
            mput(w,259+i); recent[1:i+1]=recent[0:i]; recent[0]=d
            sl=r.randrange(28); w.put(T['r'][sl],5); eb=r.getrandbits(LBI[sl]) if LBI[sl] else 0; w.put(eb,LBI[sl])
            L=LB[sl]+2+eb; last[0]=L; left-=L; produced+=L; continue
        if x<0.72:
            i=r.randint(0,7); eb=r.getrandbits(SBI[i]); d=SB[i]+1+eb
            if d>produced: continue
            mput(w,263+i); w.put(eb,SBI[i]); recent=[d]+recent[:3]; last[0]=2; left-=2; produced+=2; continue
        sl=r.randrange(28); eb=r.getrandbits(LBI[sl]) if LBI[sl] else 0
        ds=r.randrange(60)
        while DB[ds]+(1<<DBI[ds])>min(produced,1<<22) and ds>0: ds-=1
        bits=DBI[ds]
        if ds>9:
            hi = r.getrandbits(bits-4) if bits>4 else 0
            if lowrep[0]>0: low=prevlow[0]; code=None
            elif r.random()<0.05: low=prevlow[0]; code=16
            else: low=r.randrange(16); code=low
            d=DB[ds]+1+(hi<<4)+low
            if d>produced: continue
            mput(w,271+sl); w.put(eb,LBI[sl]); w.put(T['d'][ds],6)
            if bits>4: w.put(hi,bits-4)
            if code is None: lowrep[0]-=1
            else:
                w.put(T['l'][code],5)
                if code==16: lowrep[0]=15
                else: prevlow[0]=low
        else:
            db=r.getrandbits(bits) if bits else 0; d=DB[ds]+1+db
            if d>produced: continue
            mput(w,271+sl); w.put(eb,LBI[sl]); w.put(T['d'][ds],6); w.put(db,bits)
        L=LB[sl]+3+eb+(1 if d>=0x2000 else 0)+(1 if d>=0x40000 else 0)
        recent=[d]+recent[:3]; last[0]=L; left-=L; produced+=L
    # end of file marker: 00 or 01 (next file starts with new tables)
    mput(w,256); nt = r.random()<0.4 or f==nfiles-1
    w.put(0,1); w.put(1 if nt else 0,1)
    data=w.done()
    out+=struct.pack('<Qq',len(data),size+r.choice([0,0,0,5,-3]))+data
    if nt and f<nfiles-1:
        # next frame begins with tables
        first=True
sys.stdout.buffer.write(out)
