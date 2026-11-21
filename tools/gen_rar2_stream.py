# SPDX-License-Identifier: GPL-3.0-or-later
# Test-only generator of valid RAR 2.x streams (random symbols).
import random, sys, struct
class BW:
    def __init__(s): s.b=bytearray(); s.acc=0; s.n=0
    def put(s,v,n):
        for i in range(n-1,-1,-1):
            s.acc=(s.acc<<1)|((v>>i)&1); s.n+=1
            if s.n==8: s.b.append(s.acc); s.acc=0; s.n=0
    def done(s):
        if s.n: s.b.append(s.acc<<(8-s.n))
        return bytes(s.b)+b"\0"*8
def canon(lens):
    order=sorted([i for i,l in enumerate(lens) if l],key=lambda i:(lens[i],i))
    codes={}; code=0; prev=0
    for i in order:
        code <<= (lens[i]-prev); prev=lens[i]; codes[i]=code; code+=1
    return codes
LEN_BASE=[0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,32,40,48,56,64,80,96,112,128,160,192,224]
LEN_BITS=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5]
DB=[];DBITS=[];nx=0
for i in range(48):
    b=0 if i<4 else (i//2-1 if i<34 else 16); DB.append(nx); DBITS.append(b); nx+=1<<b
SB=[0,4,8,16,32,64,128,192]; SBITS=[2,2,3,4,5,6,6,6]
r=random.Random(int(sys.argv[1])); nfiles=int(sys.argv[2])
class St: pass
st=St(); st.prev=[0]*1028; st.audio=False; st.ch=1; st.cur=0
LEVEL=[5]*19; lc=canon(LEVEL)
def tables(w, first):
    st.audio = (not first) and r.random()<0.3
    keep = r.random()<0.5 and not first
    w.put(1 if st.audio else 0,1); w.put(1 if keep else 0,1)
    if not keep: st.prev=[0]*1028
    if st.audio:
        st.ch=r.randint(1,4); w.put(st.ch-1,2)
        if st.cur>=st.ch: st.cur=0
        size=257*st.ch
    else: size=298+48+28
    for l in LEVEL: w.put(l,4)
    if st.audio:
        lens=[]
        for c in range(st.ch): lens+= [9]*257
    else:
        lens=[9]*298+[6]*48+[5]*28
        # sometimes drop a few symbols (length 0)
        for _ in range(r.randint(0,3)):
            i=r.randrange(0,298)
            if i not in (256,269): lens[i]=0
    i=0
    while i<size:
        # runs of equal lengths via 16
        if i>0 and r.random()<0.1 and lens[i]==lens[i-1]:
            n=1
            while i+n<size and n<6 and lens[i+n]==lens[i-1]: n+=1
            if n>=3:
                w.put(lc[16],5); w.put(n-3,2); i+=n; continue
        if lens[i]==0:
            n=1
            while i+n<size and lens[i+n]==0 and n<138: n+=1
            if n>=11: w.put(lc[18],5); w.put(n-11,7); i+=n; continue
            if n>=3: w.put(lc[17],5); w.put(n-3,3); i+=n; continue
        w.put(lc[(lens[i]-st.prev[i])&15],5); i+=1
    st.prev[:size]=lens[:size]
    if st.audio: st.codes=[canon(lens[c*257:(c+1)*257]) for c in range(st.ch)]
    else:
        st.mc=canon(lens[:298]); st.dc=canon(lens[298:346]); st.rc=canon(lens[346:374])
        st.mlen=lens[:298]
def mput(w,sym): w.put(st.mc[sym],st.mlen[sym])
produced=0
recent=[0xffffffff]*4; rptr=0; last=[0,0xffffffff]
def inc(d,a): return sum(1 for t in a if d>=t)
def emit_match(L,d):
    global rptr
    recent[rptr]=d; rptr=(rptr+1)&3; last[0]=L; last[1]=d
out=bytearray(); first=True
for f in range(nfiles):
    w=BW(); size=r.randint(1,60000)
    if first: tables(w,True); first=False
    left=size
    while left>0:
        if st.audio:
            if r.random()<0.003: w.put(st.codes[st.cur][256],9); tables(w,False); continue
            w.put(st.codes[st.cur][r.randrange(256)],9); st.cur=(st.cur+1)%st.ch; left-=1; produced+=1; continue
        x=r.random()
        if x<0.004: mput(w,269); tables(w,False); continue
        avail=[s for s in range(298) if st.mlen[s]]
        if x<0.5 or produced<2:
            s=r.randrange(256)
            if not st.mlen[s]: continue
            mput(w,s); left-=1; produced+=1; continue
        if x<0.55:
            if last[0]==0 or last[1]>produced: continue
            mput(w,256); L,d=last; emit_match(L,d); left-=L; produced+=L; continue
        if x<0.65:
            s=r.randint(257,260)
            if not st.mlen[s]: continue
            d=recent[(rptr-(s-256))&3]
            if d>produced: continue
            mput(w,s); slot=r.randrange(28); w.put(st.rc[slot],5); eb=r.getrandbits(LEN_BITS[slot]) if LEN_BITS[slot] else 0; w.put(eb,LEN_BITS[slot])
            L=LEN_BASE[slot]+2+eb+inc(d,(0x101,0x2000,0x40000)); emit_match(L,d); left-=L; produced+=L; continue
        if x<0.75:
            s=r.randint(261,268)
            if not st.mlen[s]: continue
            i=s-261; eb=r.getrandbits(SBITS[i]); d=SB[i]+1+eb
            if d>produced: continue
            mput(w,s); w.put(eb,SBITS[i]); emit_match(2,d); left-=2; produced+=2; continue
        s=r.randint(270,297)
        if not st.mlen[s]: continue
        slot=s-270; eb=r.getrandbits(LEN_BITS[slot]) if LEN_BITS[slot] else 0
        maxd=min(produced,1<<22)
        ds=r.randrange(48)
        while DB[ds]+(1<<DBITS[ds])>maxd and ds>0: ds-=1
        db=r.getrandbits(DBITS[ds]) if DBITS[ds] else 0; d=DB[ds]+1+db
        if d>produced: continue
        mput(w,s); w.put(eb,LEN_BITS[slot]); w.put(st.dc[ds],6); w.put(db,DBITS[ds])
        L=LEN_BASE[slot]+3+eb+inc(d,(0x2000,0x40000)); emit_match(L,d); left-=L; produced+=L
    # sometimes put a table switch right after the file end
    if f<nfiles-1 and r.random()<0.3:
        if st.audio: w.put(st.codes[st.cur][256],9)
        else: mput(w,269)
        tables(w,False)
    data=w.done()
    out+=struct.pack('<Qq',len(data),size)+data
sys.stdout.buffer.write(out)
