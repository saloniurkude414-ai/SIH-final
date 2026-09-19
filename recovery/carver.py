import os, struct, hashlib
from dataclasses import dataclass, asdict

@dataclass
class CarveResult:
    offset:int; size:int; extension:str; mime:str; confidence:int; sha256:str; path:str=''

SIGS = {
    b'\xFF\xD8\xFF': ('.jpg','image/jpeg',0),
    b'\x89PNG\r\n\x1a\n': ('.png','image/png',0),
    b'GIF87a':('.gif','image/gif',0), b'GIF89a':('.gif','image/gif',0),
    b'%PDF-':('.pdf','application/pdf',0), b'PK\x03\x04':('.zip','application/zip',0),
    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':('.doc','application/msword',0),
    b'ID3':('.mp3','audio/mpeg',0), b'\x00\x00\x00\x18ftyp':('.mp4','video/mp4',0),
}

class FileCarver:
    def __init__(self, chunk_size=1024*1024): self.chunk_size=chunk_size
    def carve(self, image_path, max_results=500, progress=None):
        results=[]; size=os.path.getsize(image_path)
        with open(image_path,'rb') as f:
            data=b''; base=0
            while base < size and len(results)<max_results:
                chunk=f.read(self.chunk_size)
                if not chunk: break
                data += chunk
                for sig,(ext,mime,_) in SIGS.items():
                    pos=0
                    while True:
                        i=data.find(sig,pos)
                        if i<0: break
                        off=base-len(data)+i
                        if off>=0 and all(r.offset!=off for r in results):
                            est=self._estimate_size(data[i:],ext)
                            conf=self._confidence(data[i:],ext)
                            sample=data[i:i+min(est,4*1024*1024)]
                            results.append(CarveResult(off,est,ext,mime,conf,hashlib.sha256(sample).hexdigest()))
                        pos=i+1
                if len(data)>self.chunk_size*2:
                    base += len(data)-self.chunk_size
                    data=data[-self.chunk_size:]
                else: base += len(chunk)
                if progress: progress(min(100,int(base/max(size,1)*100)))
        return [asdict(r) for r in sorted(results,key=lambda x:x.offset)]
    def _estimate_size(self,d,ext):
        if ext=='.jpg':
            end=d.find(b'\xFF\xD9',3); return end+2 if end>0 else min(len(d),5*1024*1024)
        if ext=='.png':
            end=d.find(b'IEND',8); return end+8 if end>0 else min(len(d),5*1024*1024)
        if ext=='.pdf':
            end=d.find(b'%%EOF',5); return end+5 if end>0 else min(len(d),10*1024*1024)
        if ext=='.gif':
            end=d.find(b'\x3B',6); return end+1 if end>0 else min(len(d),5*1024*1024)
        return min(len(d),10*1024*1024)
    def _confidence(self,d,ext):
        score=65
        if ext=='.jpg' and b'\xFF\xD9' in d: score+=25
        elif ext=='.png' and b'IEND' in d: score+=25
        elif ext=='.pdf' and b'%%EOF' in d: score+=25
        elif ext=='.gif' and b'\x3B' in d: score+=25
        return min(score,99)
    def extract(self,image_path,result,out_path):
        with open(image_path,'rb') as src:
            src.seek(int(result['offset'])); data=src.read(int(result['size']))
        with open(out_path,'wb') as dst: dst.write(data)
        return hashlib.sha256(data).hexdigest()
