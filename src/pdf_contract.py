"""Render and freeze the exact PDF bytes before online confirmation."""
import io, os
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

def render_pdf(text):
    path=os.environ.get('XIN_PDF_FONT','/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc')
    if 'XinCJK' not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont('XinCJK',path,subfontIndex=0))
    output=io.BytesIO()
    normal=ParagraphStyle('body',fontName='XinCJK',fontSize=10,leading=16,wordWrap='CJK',spaceAfter=7)
    title=ParagraphStyle('title',parent=normal,fontSize=18,leading=27,alignment=1,spaceAfter=15)
    story=[]
    for i,line in enumerate(text.splitlines()):
        story.append(Paragraph(escape(line) or '&#160;',title if i==0 else normal))
    story.extend([Spacer(1,12),Paragraph('本 PDF 为锁定合同正文。是否完成在线确认须核对独立确认记录；不含伪造签名或手印。',normal)])
    def footer(c,d):
        c.setFont('XinCJK',9); c.drawRightString(A4[0]-42,28,'XIN | '+str(d.page))
    SimpleDocTemplate(output,pagesize=A4,leftMargin=42,rightMargin=42,topMargin=45,bottomMargin=45,title='XIN debt confirmation').build(story,onFirstPage=footer,onLaterPages=footer)
    return output.getvalue()
