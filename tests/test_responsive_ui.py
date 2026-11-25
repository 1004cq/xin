"""Browser layout regression, no real contracts or external network."""
from pathlib import Path
from tempfile import TemporaryDirectory
from jinja2 import Environment, FileSystemLoader, select_autoescape
from playwright.sync_api import sync_playwright
import os, shutil

ROOT=Path(__file__).resolve().parents[1]

def test_responsive_ui():
    env=Environment(loader=FileSystemLoader(ROOT/'src/templates'),autoescape=select_autoescape(['html']))
    env.filters['yuan']=lambda c:f'{c/100:.2f}'
    template=env.get_template('index.html')
    r=dict(id='a'*24,borrower='测试借款人'*8,principal=12345678,due='2028-12-31',receipt=True,revoked=False,pdf=True,proof=True,ots_state='proof_saved_unverified')
    common=dict(csrf='test-token',rows=[r,dict(r,receipt=False,borrower='另一个借款人'),dict(r,revoked=True)],r=r,id=r['id'],url='https://example.invalid/s/'+'a'*96,pin='12345678',doc='多笔借款结算及债务确认书\n'+'长文本与不可断行数字 '+('1234567890'*25)+'\n'+('多笔借款明细。'*80),sha='a'*64,pdfsha='b'*64,attachments=[dict(name='超长文件名'*40+'.pdf',size=2048)],request_path='/s/test',error=None)
    with TemporaryDirectory() as tmp, sync_playwright() as p:
        base=Path(tmp);(base/'static').mkdir();shutil.copy(ROOT/'src/static/style.css',base/'static/style.css')
        # Absolute asset paths are intercepted locally to preserve actual template URLs.
        browser=p.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH') or None,args=['--no-sandbox'])
        cases=0
        for scheme in ('light','dark'):
            page=browser.new_page(color_scheme=scheme)
            page.route('https://xin.test/**',lambda route:route.fulfill(status=200,content_type='text/css',body=(base/'static/style.css').read_text()) if route.request.url.endswith('/style.css') else route.fulfill(status=200,content_type='application/javascript',body='') if route.request.url.endswith('/passkey.js') else route.fulfill(status=200,content_type='application/javascript',body=(ROOT/'src/static/ui.js').read_text()) if route.request.url.endswith('/ui.js') else route.fulfill(status=200,content_type='image/svg+xml',body=(ROOT/'src/static/mark.svg').read_text()) if route.request.url.endswith('/mark.svg') else route.fulfill(status=404,body=''))
            for width,height in [(320,568),(390,844),(768,1024),(844,390),(1024,768),(1440,900)]:
                page.set_viewport_size({'width':width,'height':height})
                for view in ('login','admin','new','invite','detail','unlock','sign','signed','used'):
                    html=template.render(view=view,**common).replace('<head>','<head><base href="https://xin.test/">')
                    page.set_content(html,wait_until='load')
                    assert page.locator('h1').count()==1,view
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1'),(view,width,scheme,page.evaluate('document.documentElement.scrollWidth'))
                    for button in page.locator('button:visible,.button:visible').all():
                        box=button.bounding_box();assert box and box['height']>=44 and box['x']>=-1 and box['x']+box['width']<=width+1,(view,width,scheme,box)
                    if view=='admin':
                        page.locator('#record-search').fill('另一个')
                        assert page.locator('[data-record]:visible').count()==1
                        page.locator('#record-filter').select_option('confirmed')
                        assert page.locator('[data-record]:visible').count()==0
                        assert page.locator('#filter-empty').is_visible()
                        page.locator('#record-search').fill('')
                        page.locator('#record-filter').select_option('all')
                        assert page.locator('[data-record]:visible').count()==3
                    if view=='invite':
                        assert page.locator('[data-copy]').count()==2
                        assert page.locator('#invite-pin').input_value()=='12345678'
                    if view=='sign':
                        assert page.locator('#passkey-form input[name=sha]').input_value()=='a'*64
                        assert page.locator('#passkey-form input[name=pdfsha]').input_value()=='b'*64
                        assert page.locator('#passkey-form input[name=consent]').get_attribute('required') is not None
                    if view in ('detail','sign','new'):
                        grid=page.locator('.workspace-grid')
                        assert grid.evaluate("e=>getComputedStyle(e).gridTemplateColumns.split(' ').length")== (2 if width>=960 else 1)
                    cases+=1
            page.close()
        browser.close();print(f'{cases} responsive page combinations passed')

if __name__=='__main__':test_responsive_ui()
