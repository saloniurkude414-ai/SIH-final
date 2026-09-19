import os
SIGNATURES={
 b'\xFF\xD8\xFF':('JPEG Image','.jpg'), b'\x89PNG\r\n\x1a\n':('PNG Image','.png'), b'GIF87a':('GIF Image','.gif'), b'GIF89a':('GIF Image','.gif'), b'%PDF-':('PDF Document','.pdf'), b'PK\x03\x04':('ZIP Archive','.zip'), b'ID3':('MP3 Audio','.mp3'), b'\x00\x00\x00\x18ftyp':('MP4 Video','.mp4')}
def detect_signature(path):
 try:
  with open(path,'rb') as f: head=f.read(32)
  for sig,(typ,ext) in SIGNATURES.items():
   if head.startswith(sig): return {'type':typ,'extension':ext}
 except OSError: pass
 return None
