import os, hashlib, mimetypes, time
from .signatures import detect_signature
from .carver import FileCarver

class RecoveryEngine:
    def __init__(self): self.carver=FileCarver()
    def scan_directory(self,path,deep=False,progress=None):
        rows=[]; files=[]
        for root,_,names in os.walk(path):
            for n in names:
                p=os.path.join(root,n)
                try:
                    st=os.stat(p); files.append((p,st))
                except OSError: continue
        total=max(len(files),1)
        for i,(p,st) in enumerate(files,1):
            try:
                sig=detect_signature(p); ext=os.path.splitext(p)[1].lower(); mime,_=mimetypes.guess_type(p)
                status='SIGNATURE VERIFIED' if sig and sig.get('extension','')==ext else ('SIGNATURE MISMATCH' if sig else 'UNKNOWN TYPE')
                with open(p,'rb') as f: sample=f.read(1024*1024)
                rows.append({'file_name':os.path.basename(p),'path':p,'detected_type':sig.get('type','UNKNOWN') if sig else 'UNKNOWN','extension':ext,'size':st.st_size,'status':status,'signature_mismatch':status=='SIGNATURE MISMATCH','mime':mime or 'application/octet-stream','modified':time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(st.st_mtime)),'sha256':hashlib.sha256(sample).hexdigest()})
            except Exception as e: rows.append({'file_name':os.path.basename(p),'path':p,'detected_type':'ERROR','extension':'','size':0,'status':str(e),'signature_mismatch':False})
            if progress: progress(int(i/total*100))
        return rows
    def deep_carve(self,image_path,progress=None): return self.carver.carve(image_path,progress=progress)
