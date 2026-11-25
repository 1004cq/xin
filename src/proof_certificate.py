"""Private PDF report with QR containing only the verifier URL and hash fragment."""
import io, os, re, textwrap
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.graphics import renderPDF
from reportlab.lib.colors import HexColor

def render_certificate(r,base,kind):
    if r.get('chain')!='bitcoin-mainnet' or r.get('confirmations_at_verification',0)<6:raise ValueError('unverified proof')
    for field in ('file_sha256','proof_sha256','block_hash'):
        if not re.fullmatch('[0-9a-f]{64}',r[field]):raise ValueError('bad digest')
    if 'XinCJK' not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont('XinCJK',os.environ.get('XIN_PDF_FONT','/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc'),subfontIndex=0))
    out=io.BytesIO();c=canvas.Canvas(out,pagesize=A4);w,h=A4;c.setTitle('XIN Bitcoin proof report')
    c.setFillColor(HexColor('#255cb1'));c.rect(0,h-12,w,12,fill=1,stroke=0)
    c.setFont('XinCJK',24);c.drawString(44,h-66,'XIN 信 · 数字存证凭证')
    c.setFont('XinCJK',12);c.drawString(44,h-94,'Bitcoin 主网节点历史核验报告 / '+kind)
    c.setFillColor(HexColor('#182334'));y=h-140
    rows=[('原始文件 SHA-256',r['file_sha256']),('OTS 证明 SHA-256',r['proof_sha256']),('区块高度',str(r['height'])),('区块哈希',r['block_hash']),('区块时间（UTC）',r['block_time_utc']),('核验时确认数',str(r['confirmations_at_verification'])),('核验时间（UTC）',r['verified_at_utc'])]
    for label,value in rows:
        c.setFont('XinCJK',11);c.drawString(44,y,label);y-=20
        c.setFont('Courier',10);c.drawString(44,y,value);y-=30
    url=base+'/verify#sha256='+r['file_sha256']
    qr=QrCodeWidget(url);bounds=qr.getBounds();size=98
    d=Drawing(size,size,transform=[size/(bounds[2]-bounds[0]),0,0,size/(bounds[3]-bounds[1]),0,0]);d.add(qr)
    renderPDF.draw(d,c,44,105)
    c.setFont('XinCJK',10);c.drawString(157,183,'扫描二维码进入验证中心')
    c.drawString(157,164,'指纹位于 URL 片段，不用于查询合同。')
    c.drawString(157,145,'保留原文件及 .ots，使用独立节点复核。')
    c.drawString(44,78,'本报告仅反映核验时状态，不证明法定身份、借款事实或法律效力。')
    c.drawString(44,59,'非公证书、非司法认证、非 CA 电子签名证书。')
    c.showPage();c.save();return out.getvalue()
