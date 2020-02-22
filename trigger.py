import re, time, requests, os, sys, json, socket, sqlite3, hashlib
##from requests_html import HTMLSession
from func_timeout import func_set_timeout, FunctionTimedOut
from selenium import webdriver
from selenium.common.exceptions import TimeoutException,UnexpectedAlertPresentException
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.select import Select
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support import expected_conditions as EC

#初始url文件，完整路径
filename = 'E:/passive_scan_study/test/url.txt'
file_path = filename.rsplit('/',1)[0]+'/'
#用于上传的payload的文件夹，反连平台自备
data_path = 'E:/passive_scan_study/请自备/'
ip_domain_number = 5      #一个IP绑定下几个域名时集合域名进行去重
ip_path_number = 1        #一个IP路径下允许重复的链接数
domain_url_number = 600   #一个域名下允许测试的链接数
domain_path_number = 10   #一个域名路径下允许重复的链接数
dynamic_path_number = 1   #一个域名下允许重复的动态链接数
ip_operate_number = 1     #一个IP下允许重复的用户操作数
domain_operate_number = 1 #一个域名下允许重复的用户操作数
timeout = 15              #一个tab加载等待的时间

#过滤掉的url后缀
pass_file_suffix = {'.apk', '.woff', '.ttf', '.js','.css','.ai','.bmp','.cdr','.dxf','.emf','.eps','.exif','.flic','.fpx','.gif','.hdri','.ico','.jpeg','.jpg','.dpg','.pcd','.pcx','.png','.psd','.raw','.svg','.tga','.tif','.ufo','.webp','.wmf','.3gp','.amv','.asf','.avi','.bmp','.dat','.f4v','.flv','.imv','.m4v','.mkv','.mov','.mp3','.mp4','.mpeg1','.mpeg2','.mpeg4','.mpg','.mts','.qsv','.rm','.rmvb','.ts','.vob','.wav','.wma','.wmv','.xv','.zip','.rar','.gz','.7z','.exe','.pdf','.ppt','.doc','.docx','.xls','.xlsx','.csv','.wps'}
#要触发的函数
html_dom_event = ['onabort','onactivate','onafterprint','onafterupdate','onanimationend','onanimationiteration','onanimationstart','onautocomplete','onautocompleteerror','onbeforeactivate','onbeforecopy','onbeforecut','onbeforedeactivate','onbeforeeditfocus','onbeforepaste','onbeforeprint','onbeforeunload','onbeforeupdate','onbegin','onblur','onbounce','oncancel','oncanplay','oncanplaythrough','oncellchange','onchange','onclick','onclose','oncompassneedscalibration','oncontextmenu','oncontrolselect','oncopy','oncuechange','oncut','ondataavailable','ondatasetchanged','ondatasetcomplete','ondblclick','ondeactivate','ondevicelight','ondevicemotion','ondeviceorientation','ondeviceproximity','ondrag','ondragdrop','ondragend','ondragenter','ondragexit','ondragleave','ondragover','ondragstart','ondrop','ondurationchange','onemptied','onend','onended','onerror','onerrorupdate','onexit','onfilterchange','onfinish','onfocus','onfocusin','onfocusout','onformchange','onformchange ','onforminput','onforminput ','ongesturechange','ongestureend','ongesturestart','onhaschange','onhashchange','onhelp','oninput','oninvalid','onkeydown','onkeypress','onkeyup','onlanguagechange','onlayoutcomplete','onload','onloadeddata','onloadedmetadata','onloadstart','onlosecapture','onmediacomplete','onmediaerror','onmessage','onmousedown','onmouseenter','onmouseleave','onmousemove','onmouseout','onmouseover','onmouseup','onmousewheel','onmove','onmoveend','onmovestart','onmozfullscreenchange','onmozfullscreenerror','onmozpointerlockchange','onmozpointerlockerror','onmsgesturechange','onmsgesturedoubletap','onmsgesturehold','onmsgesturerestart','onmsinertiastart','onmspointercancel','onmspointerdown','onmspointerenter','onmspointerhover','onmspointerleave','onmspointermove','onmspointerout','onmspointerover','onmspointerup','onoffline','ononline','onorientationchange','onoutofsync','onpagehide','onpageshow','onpaste','onpause','onplay','onplaying','onpopstate','onprogress','onpropertychange','onratechange','onreadystatechange','onreceived','onredo','onrepeat','onreset','onresize','onresizeend','onresizestart','onresume','onreverse','onrowdelete','onrowenter','onrowexit','onrowinserted','onrowsdelete','onrowsinserted','onscroll','onsearch','onseek','onseeked','onseeking','onselect','onselectionchange','onselectstart','onshow','onstalled','onstart','onstop','onstorage','onsubmit','onsuspend','onsynchrestored','ontimeerror','ontimeupdate','ontoggle','ontouchcancel','ontouchend','ontouchmove','ontouchstart','ontrackchange','ontransitionend','onundo','onunload','onurlflip','onuserproximity','onvolumechange','onwaiting','onwebkitanimationend','onwebkitanimationiteration','onwebkitanimationstart','onwebkitmouseforcechanged','onwebkitmouseforcedown','onwebkitmouseforceup','onwebkitmouseforcewillbegin','onwebkittransitionend','onwebkitwillrevealbottom','onwheel','onzoom']
username = 'MyP3nt35tU53rn4m3'  #用户名
password = 'MyP3nt35tP455w0rd'  #密码
phonenumber = '17134025331' #接码平台的手机号码
email = 'youremail@protonmail.com'  #你的匿名邮箱
textarea = 'MyP3nt35tT3xt4r34_11u14ngm40_MyP3nt35tT3xt4r34'  #填充文本1
other_text = '0123456789'   #填充文本2

#url黑名单
url_blacklist = []
#以此开头的url黑名单
url_blacklist_startswith = {}
#用户交互黑名单
operate_blacklist = {}

#用于登陆扫描的cookie
cookie_tmp = ''
##cookie_tmp = 'user_id=bca1904d-df93-4d5c-ad36-e248876bf337; g_uid=7df5d117-239d-402a-9167-2ff4b0ff1c0f'
if cookie_tmp:
    cookie_tmp2 = re.split('=|;',cookie_tmp)
    cookie = []
    for i in range(0,len(cookie_tmp2),2):
        cookie.append({'name':cookie_tmp2[i].strip(),'value':cookie_tmp2[i+1]})
else:
    cookie = []
    
domains = set()
domains_tuple = []
stars = []
domain_suffix = []
rule=r'(\d{1,3}\.){3}\d{1,3}'
compiled_rule=re.compile(rule)

#域名后缀
with open('domain_suffix.txt','r',encoding='utf-8')as f:
    lists = f.readlines()
    for i in lists:
        domain_suffix.append(i.strip())

#主域名列表,同文件夹下star.txt
if os.path.exists(file_path+'star.txt'):
    with open(file_path+'star.txt','r',encoding='utf-8')as f:
        lists = f.readlines()
        for i in lists:
            stars.append(i.strip())
else:
    for i in open(filename,'r',encoding='utf8'):
        stars.append(i.split('/')[2].split('?',1)[0].split(':',1)[0])

#配置chromium
chromedriver_path = 'E:/Python36/chromedriver.exe'
chromeOptions = webdriver.ChromeOptions()
#chromeOptions.binary_location = "E:/chrome-win/chrome.exe"
##chromeOptions.add_argument('user-agent="Mozilla/5.0 (iPhone; CPU iPhone OS 8_0 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Mobile/12A365 MicroMessenger/5.4.1 NetType/WIFI"')#模拟微信客户端
chromeOptions.add_argument('--no-sandbox')  #root权限运行
chromeOptions.add_argument('--disable-dev-shm-usage')   #性能兼容模式
chromeOptions.add_argument('--disable-gpu') #谷歌文档提到需要加上这个属性来规避bug
##chromeOptions.add_argument('--hide-scrollbars') #隐藏滚动条, 应对一些特殊页面
##chromeOptions.add_argument('--headless') #无界面
chromeOptions.add_experimental_option('excludeSwitches', ['enable-automation']) #规避selenium检测
chromeOptions.add_argument('--disable-plugins') #禁止加载插件
##chromeOptions.add_argument('--proxy-server=http://127.0.0.1:6666')  #转发到下一个模块
##chromeOptions.add_argument("--auto-open-devtools-for-tabs")
prefs={"profile.managed_default_content_settings.popups":0, #禁止alert，好像没用
       "download.default_directory": "zz:\\",#写个错的盘，不让它自动下载
       "profile.managed_default_content_settings.images":2, #不加载图片
       "profile.managed_default_content_settings.notifications":2}  #禁止弹出提醒框
chromeOptions.add_experimental_option('prefs',prefs)
driver = webdriver.Chrome(executable_path = chromedriver_path, chrome_options=chromeOptions, service_log_path = file_path+'DevTools.log')
driver.set_page_load_timeout(timeout)   #一个页面加载的最大等待时长
driver.set_script_timeout(timeout)  #javascript执行的最大等待时长
##driver.implicitly_wait(5)
##driver.maximize_window()
##driver.execute_script('window.alert=function(str){return;};')

#获取主域名
def get_main_domain(i):
    try:
        if i.split('.')[-2] in domain_suffix:
            if len(i.split('.')) == 2:
                main_domain = i.split('.')[-2] + '.' + i.split('.')[-1]
            else:
                if i.split('.')[-3] == 'www':
                    main_domain = i.split('.')[-2] + '.' + i.split('.')[-1]
                else:
                    main_domain = i.split('.')[-3] + '.' + i.split('.')[-2] + '.' + i.split('.')[-1]
        else:
            if not compiled_rule.search(i):
                main_domain = i.split('.')[-2] + '.' + i.split('.')[-1]
            else:
                main_domain = i
    except:
        main_domain = None
    return main_domain

#判断是否子域名或ip
def check_star(current_url,domain):
    main_domain = get_main_domain(domain)

    if ((main_domain in stars) or (domain in stars)):
        return True
    elif (compiled_rule.search(domain) and (current_url.split('/')[2] == main_domain)):
        return True
    else:
        return False

#获取某个url已入库的数量
def url_get_number(domain_or_ip, regex, db):
    if db == 'domain_url_number':
        path = domain_or_ip
    elif db == 'dynamic_path_number':
        path = regex
    elif len(regex.split('/')) > 4:#两层及以上path
        path = regex.rsplit('/',1)[0]
    else:
        if re.match('http[s]?://[^\/]+/\w+\?',regex):
            path = regex.split('?')[0]
        elif re.match('http[s]?://[^\/]+/\w+\#',regex):
            path = regex.split('#')[0]
        else:
            path = regex.split('/')[0] + '//' + regex.split('/')[2]
    if db == 'domain_url_number':
        path_num = [i[0] for i in c.execute("SELECT number from "+db+" where domain_url=?",(domain_or_ip,))]
    else:
        path_num = [i[0] for i in c.execute("SELECT number from "+db+" where %s=?"%(db.rsplit('_',1)[0]),(path,))]
    if path_num:
        path_num = path_num[0]
    else:
        path_num = 0
    return [path,path_num]

#判断url是否重复的子函数
def url_tmp_function(ip_path, ip_path_num, domain, regex):
    flag = False
    if ip_path_num != 0:

        [domain_url,domain_url_num] = url_get_number(domain, regex, 'domain_url_number')
        if domain_url_num < domain_url_number:#未超出
            if domain_url_num != 0:
                
                [domain_path,domain_path_num] = url_get_number(domain, regex, 'domain_path_number')
                if domain_path_num < domain_path_number:#未超出
                    if domain_path_num != 0:

                        [dynamic_path,dynamic_path_num] = url_get_number(domain, regex, 'dynamic_path_number')
                        if dynamic_path_num < dynamic_path_number:#未超出
                            if dynamic_path_num != 0:

                                c.execute('UPDATE dynamic_path_number set number=? where dynamic_path=?',(dynamic_path_num+1, dynamic_path))
                            else:
                                c.execute('INSERT INTO dynamic_path_number (dynamic_path,number) VALUES (?,1)',(dynamic_path,))
                            flag = True
                            c.execute('UPDATE domain_path_number set number=? where domain_path=?',(domain_path_num+1, domain_path))
                            c.execute('UPDATE domain_url_number set number=? where domain_url=?',(domain_url_num+1, domain_url))
                            c.execute('UPDATE ip_path_number set number=? where ip_path=?',(ip_path_num+1, ip_path))
                    else:
                        [dynamic_path,dynamic_path_num] = url_get_number(domain, regex, 'dynamic_path_number')
                        if dynamic_path_num < dynamic_path_number:#未超出
                            if dynamic_path_num != 0:

                                c.execute('UPDATE dynamic_path_number set number=? where dynamic_path=?',(dynamic_path_num+1, dynamic_path))
                            else:
                                c.execute('INSERT INTO dynamic_path_number (dynamic_path,number) VALUES (?,1)',(dynamic_path,))
                            flag = True
                            c.execute('INSERT INTO domain_path_number (domain_path,number) VALUES (?,1)',(domain_path,))
                            c.execute('UPDATE domain_url_number set number=? where domain_url=?',(domain_url_num+1, domain_url))
                            c.execute('UPDATE ip_path_number set number=? where ip_path=?',(ip_path_num+1, ip_path))
            else:
                [domain_path,domain_path_num] = url_get_number(domain, regex, 'domain_path_number')
                if domain_path_num < domain_path_number:#未超出
                    if domain_path_num != 0:

                        [dynamic_path,dynamic_path_num] = url_get_number(domain, regex, 'dynamic_path_number')
                        if dynamic_path_num < dynamic_path_number:#未超出
                            if dynamic_path_num != 0:

                                c.execute('UPDATE dynamic_path_number set number=? where dynamic_path=?',(dynamic_path_num+1, dynamic_path))
                            else:
                                c.execute('INSERT INTO dynamic_path_number (dynamic_path,number) VALUES (?,1)',(dynamic_path,))
                            flag = True
                            c.execute('UPDATE domain_path_number set number=? where domain_path=?',(domain_path_num+1, domain_path))
                            c.execute('INSERT INTO domain_url_number (domain_url,number) VALUES (?,1)',(domain_url,))
                            c.execute('UPDATE ip_path_number set number=? where ip_path=?',(ip_path_num+1, ip_path))
                    else:
                        [dynamic_path,dynamic_path_num] = url_get_number(domain, regex, 'dynamic_path_number')
                        if dynamic_path_num < dynamic_path_number:#未超出
                            if dynamic_path_num != 0:

                                c.execute('UPDATE dynamic_path_number set number=? where dynamic_path=?',(dynamic_path_num+1, dynamic_path))
                            else:
                                c.execute('INSERT INTO dynamic_path_number (dynamic_path,number) VALUES (?,1)',(dynamic_path,))
                            flag = True
                            c.execute('INSERT INTO domain_path_number (domain_path,number) VALUES (?,1)',(domain_path,))
                            c.execute('INSERT INTO domain_url_number (domain_url,number) VALUES (?,1)',(domain_url,))
                            c.execute('UPDATE ip_path_number set number=? where ip_path=?',(ip_path_num+1, ip_path))
                    
    else:
        [domain_url,domain_url_num] = url_get_number(domain, regex, 'domain_url_number')
        if domain_url_num < domain_url_number:#未超出
            if domain_url_num != 0:
                
                [domain_path,domain_path_num] = url_get_number(domain, regex, 'domain_path_number')
                if domain_path_num < domain_path_number:#未超出
                    if domain_path_num != 0:

                        [dynamic_path,dynamic_path_num] = url_get_number(domain, regex, 'dynamic_path_number')
                        if dynamic_path_num < dynamic_path_number:#未超出
                            if dynamic_path_num != 0:

                                c.execute('UPDATE dynamic_path_number set number=? where dynamic_path=?',(dynamic_path_num+1, dynamic_path))
                            else:
                                c.execute('INSERT INTO dynamic_path_number (dynamic_path,number) VALUES (?,1)',(dynamic_path,))
                            flag = True
                            c.execute('UPDATE domain_path_number set number=? where domain_path=?',(domain_path_num+1, domain_path))
                            c.execute('UPDATE domain_url_number set number=? where domain_url=?',(domain_url_num+1, domain_url))
                            c.execute('INSERT INTO ip_path_number (ip_path,number) VALUES (?,1)',(ip_path,))
                    else:
                        [dynamic_path,dynamic_path_num] = url_get_number(domain, regex, 'dynamic_path_number')
                        if dynamic_path_num < dynamic_path_number:#未超出
                            if dynamic_path_num != 0:

                                c.execute('UPDATE dynamic_path_number set number=? where dynamic_path=?',(dynamic_path_num+1, dynamic_path))
                            else:
                                c.execute('INSERT INTO dynamic_path_number (dynamic_path,number) VALUES (?,1)',(dynamic_path,))
                            flag = True
                            c.execute('INSERT INTO domain_path_number (domain_path,number) VALUES (?,1)',(domain_path,))
                            c.execute('UPDATE domain_url_number set number=? where domain_url=?',(domain_url_num+1, domain_url))
                            c.execute('INSERT INTO ip_path_number (ip_path,number) VALUES (?,1)',(ip_path,))
            else:
                [domain_path,domain_path_num] = url_get_number(domain, regex, 'domain_path_number')
                if domain_path_num < domain_path_number:#未超出
                    if domain_path_num != 0:

                        [dynamic_path,dynamic_path_num] = url_get_number(domain, regex, 'dynamic_path_number')
                        if dynamic_path_num < dynamic_path_number:#未超出
                            if dynamic_path_num != 0:

                                c.execute('UPDATE dynamic_path_number set number=? where dynamic_path=?',(dynamic_path_num+1, dynamic_path))
                            else:
                                c.execute('INSERT INTO dynamic_path_number (dynamic_path,number) VALUES (?,1)',(dynamic_path,))
                            flag = True
                            c.execute('UPDATE domain_path_number set number=? where domain_path=?',(domain_path_num+1, domain_path))
                            c.execute('INSERT INTO domain_url_number (domain_url,number) VALUES (?,1)',(domain_url,))
                            c.execute('INSERT INTO ip_path_number (ip_path,number) VALUES (?,1)',(ip_path,))
                    else:
                        [dynamic_path,dynamic_path_num] = url_get_number(domain, regex, 'dynamic_path_number')
                        if dynamic_path_num < dynamic_path_number:#未超出
                            if dynamic_path_num != 0:

                                c.execute('UPDATE dynamic_path_number set number=? where dynamic_path=?',(dynamic_path_num+1, dynamic_path))
                            else:
                                c.execute('INSERT INTO dynamic_path_number (dynamic_path,number) VALUES (?,1)',(dynamic_path,))
                            flag = True
                            c.execute('INSERT INTO domain_path_number (domain_path,number) VALUES (?,1)',(domain_path,))
                            c.execute('INSERT INTO domain_url_number (domain_url,number) VALUES (?,1)',(domain_url,))
                            c.execute('INSERT INTO ip_path_number (ip_path,number) VALUES (?,1)',(ip_path,))
    conn.commit()
    return flag

#判断url是否重复                        
def url_check_duplicates(url):
    regex = get_regex(url)
    flag = False
    try:
        domain = regex.split('/')[2].split('?',1)[0].split(':',1)[0]
        ip = socket.gethostbyname(domain)
    except:
        pass
    else:
        domain_list = [i[0] for i in c.execute('SELECT domain from ip_domain where ip=?',(ip,))]
        domain_list_len = len(domain_list)
        if domain not in domain_list:
            c.execute('INSERT INTO ip_domain (ip,domain) VALUES (?, ?)',(ip, domain))
            conn.commit()
            domain_list_len += 1
        ip_path = regex.replace(domain,ip,1)
        if domain_list_len > ip_domain_number:#超出绑定域名数
            
            [ip_path,ip_path_num] = url_get_number(ip, ip_path, 'ip_path_number')
            if ip_path_num < ip_path_number:#未超出
                flag = url_tmp_function(ip_path, ip_path_num, domain, regex)
        else:
            [ip_path,ip_path_num] = url_get_number(ip, ip_path, 'ip_path_number')
            flag = url_tmp_function(ip_path, ip_path_num, domain, regex)
    return flag    

#获取删除值后的url
def get_regex(craw_context):
    craw_context = craw_context.lower().strip()
                        
    position = [i.start() for i in re.finditer('/', craw_context)]
    if len(position) >2:
        path = craw_context[position[2]:]
        strlist = re.split('\/|\:|\?|=|\&|\#',path)        
        craw_context_regex = craw_context
        value = [i.start() for i in re.finditer('=', craw_context_regex)]

        if value:            
            value1 = [i.start() for i in re.finditer('\/|\:|\?|\&|\#', craw_context_regex)]            
            if value1[-1] < value[-1]:
                craw_context_regex = craw_context_regex[:value[-1]+1]                                                                                                                                                
            for i in reversed(value):
                for j in value1:
                    if j > i:
                        craw_context_regex = craw_context_regex[0:i+1] + craw_context_regex[j:]
                        break
                    
        for i in strlist:
            if len(i)>20:
                craw_context_regex=craw_context_regex.replace(i,'')

        regex = craw_context[0:position[2]] + re.sub(r'([\d]+)','',craw_context_regex[position[2]:len(craw_context_regex)])

    else:
        regex = craw_context
    return regex

#获取某个operate已入库的数量
def operate_get_number(domain_or_ip, _hash, db):
    operate_num = [i[0] for i in c.execute('SELECT number from '+db+' where %s=? and hash=?'%(db.split('_',1)[0]),(domain_or_ip, _hash))]
    if operate_num:
        operate_num = operate_num[0]
    else:
        operate_num = 0
    return operate_num

#判断operate是否重复的子函数
def operate_tmp_function(ip_operate_num, domain, ip, _hash):
    flag = False
    if ip_operate_num != 0:
        domain_operate_num = operate_get_number(domain, _hash, 'domain_operate_number')
        if domain_operate_num < domain_operate_number:#未超出

            if domain_operate_num != 0:
                c.execute('UPDATE domain_operate_number set number = ? where domain = ? and hash = ?',(str(domain_operate_num+1), domain, _hash))
            else:
                c.execute('INSERT INTO domain_operate_number (domain,hash,number) VALUES (?,?,1)',(domain,_hash))
            c.execute('UPDATE ip_operate_number set number = ? where ip = ? and hash = ?',(str(ip_operate_num+1), ip, _hash))
            flag = True
    else:
        domain_operate_num = operate_get_number(domain, _hash, 'domain_operate_number')
        if domain_operate_num < domain_operate_number:#未超出

            if domain_operate_num != 0:
                c.execute('UPDATE domain_operate_number set number = ? where domain = ? and hash = ?',(str(domain_operate_num+1), domain, _hash))
            else:
                c.execute('INSERT INTO domain_operate_number (domain,hash,number) VALUES (?,?,1)',(domain,_hash))
            c.execute('INSERT INTO ip_operate_number (ip,hash,number) VALUES (?,?,1)',(ip, _hash))
            flag = True
    conn.commit()
    return flag

#判断operate是否重复                        
def operate_check_duplicates(domain, _hash):
    flag = False
    try:
        ip = socket.gethostbyname(domain)
    except:
        pass
    else:
        domain_list = [i[0] for i in c.execute('SELECT domain from ip_domain where ip=?',(ip,))]
        domain_list_len = len(domain_list)
        if domain_list_len > ip_domain_number:#超出绑定域名数
            
            ip_operate_num = operate_get_number(ip, _hash, 'ip_operate_number')
            if ip_operate_num < ip_operate_number:#未超出
                flag = operate_tmp_function(ip_operate_num, domain, ip, _hash)
        else:
            ip_operate_num = operate_get_number(ip, _hash, 'ip_operate_number')
            flag = operate_tmp_function(ip_operate_num, domain, ip, _hash)
    return flag

#kill chromium进程
def taskkill_pid():
    while(1):
        try:
            global driver
            print('[taskkill_pid]')
            for i in open(file_path+'DevTools.log','r',encoding='utf8'):
                if 'debuggerAddress' in i:
                    DebugPort = i.split('"')[3].split(':')[1]
                    break
            pid_list=set()
            for i in os.popen('netstat -ano|findstr 127.0.0.1:'+DebugPort).read().split('\n'):
                if i.split(' ')[-1]:
                    pid_list.add(i.split(' ')[-1])
            for i in  pid_list:
                os.popen('taskkill /PID '+i)
            os.popen('taskkill /im chromedriver.exe /F')
            driver.quit()
            driver = webdriver.Chrome(executable_path = chromedriver_path, chrome_options=chromeOptions, service_log_path = file_path+'DevTools.log')
            return driver
        except Exception as e:
            print(str(e))

#打开url	
@func_set_timeout(timeout)
def driver_get(current_url = None):
    global driver
    pass_check = 0
    handle_url = ''

    while(1):
        try:#前面还有两个设置
            if current_url:
                driver.get(current_url)
                if cookie:
                    driver.delete_all_cookies()
                    for i in cookie:
                        driver.add_cookie(i)
            else:
                handle_url = driver.current_url.strip('/')
            break
        except UnexpectedAlertPresentException:
            pass
        except TimeoutException:
            try:
                driver.execute_script('window.stop()')# 报错后就强制停止加载
            except:
                driver = taskkill_pid()
                pass_check = 1
                break           

    if current_url:
        return pass_check
    else:
        return [pass_check,handle_url]

#处理打开的窗口
def deal_with_tabs():
    global driver
    handles = driver.window_handles
    while(len(handles)):
##        print(len(handles))
        driver.switch_to.window(handles[-1])
        handle_url = False
        try:
            [pass_check,handle_url] = driver_get()
        except FunctionTimedOut:
            print('-----deal_with_tabs-----timeout-----')
            try:
                if len(handles) != 1:
                    driver.get('https://www.baidu.com')
                    driver.close()
                handles.pop(-1)
                continue
            except:
                driver = taskkill_pid()
                break
        else:
            if pass_check:
                break
            if ((not pass_check) and handle_url):
                try:
                    if check_star(current_url, handle_url.split('/')[2].split('?',1)[0].split(':',1)[0]):
                        if url_check_duplicates(handle_url):
                            print(handle_url)
                            domains.append(handle_url)
                            c.execute('INSERT INTO task (url) VALUES (?)',(handle_url,))
                except:
                    with open(file_path+'crash','a',encoding='utf-8') as f:
                        f.write(handle_url+'\n')

        if (handle_url and handle_url.startswith('chrome://print')):
            ActionChains(driver).send_keys(Keys.TAB).send_keys(Keys.ENTER).perform()
        elif len(handles) != 1:
            driver.close()
        handles.pop(-1)

#删除已完成的任务
def delete_task(current_url):
    with open(file_path+'pass.txt','a',encoding='utf-8') as f:
        f.write(current_url+'\n')
    domains.pop(0)
    c.execute("DELETE from task where url=?",(current_url,))
    conn.commit()
    print('----------当前任务数：'+str(len(domains))+'----------')

#读取数据库任务
if os.path.exists(file_path+'database.db'):
    conn = sqlite3.connect(file_path+'database.db')
    c = conn.cursor()
    domains = [i[0] for i in c.execute('SELECT * from task')]
#新建数据库
else:
    conn = sqlite3.connect(file_path+'database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE ip_domain (ip char not null,domain char not null);''')
    c.execute('''CREATE TABLE domain_path_number (domain_path char not null,number int not null);''')
    c.execute('''CREATE TABLE ip_path_number (ip_path char not null,number int not null);''')
    c.execute('''CREATE TABLE dynamic_path_number (dynamic_path char not null,number int not null);''')
    c.execute('''CREATE TABLE domain_url_number (domain_url char not null,number int not null);''')
    c.execute('''CREATE TABLE task (url char not null);''')
##    c.execute('''CREATE TABLE domain_operate_number (domain char not null,tag char not null,id char not null,name char not null,type char not null,number int not null);''')
##    c.execute('''CREATE TABLE ip_operate_number (ip char not null,tag char not null,id char not null,name char not null,type char not null,number int not null);''')
    c.execute('''CREATE TABLE domain_operate_number (domain char not null,hash char not null,number int not null);''')
    c.execute('''CREATE TABLE ip_operate_number (ip char not null,hash char not null,number int not null);''')
    conn.commit()
    with open(filename,'r',encoding='utf-8')as f:
        lists = f.readlines()
        for i in lists:
            if i.split('/')[2].split('?',1)[0] != i.split('/')[2]:
                url = i.replace('?','/',1).strip('\r\n/#?')
            else:
                url = i.strip('\r\n/#?')
            if url_check_duplicates(url):
                domains.add(i.strip())
                domains_tuple.append((i.strip(),))
    c.executemany("INSERT INTO task(url) VALUES(?)",domains_tuple)
    conn.commit()
    domains = list(domains)

#main
print('----------当前任务数：'+str(len(domains))+'----------')
while(len(domains) > 0):
    current_url = domains[0]
    print('current_url: '+current_url)

    try:
        pass_check = driver_get(current_url)
        while(1):
            try:
                data = re.sub('<!--.*?-->','',driver.page_source)
                break
            except UnexpectedAlertPresentException:
                pass
            except Exception as e:
                print(str(e))
                delete_task(current_url)
                break
        current_url_redirection = driver_get()[1]
        if not check_star(current_url, current_url_redirection.split('/')[2].split('?',1)[0].split(':',1)[0]):
            delete_task(current_url)
            continue
        for i in url_blacklist_startswith:
            if current_url_redirection.startswith(i):
                pass_check = True
                break
        if pass_check:
            delete_task(current_url)
            continue
    except (FunctionTimedOut, TimeoutException, IndexError):
        print('-----while-----timeout-----')
        driver = taskkill_pid()
        delete_task(current_url)
        continue

    urls = set(re.findall('<a.*?>',data))
    task_list = []
    print('url_count:'+str(len(urls)))
    for i in urls:
        css_selector = (i.strip(' /<>').replace('" ','"][')+']').replace(' ','[',1).replace(']["',' "')
        try:
            url = driver.find_element_by_css_selector(css_selector).get_attribute("href")
        except:#轮播
            continue
        if (not url or (url and ({url[-3:],url[-4:],url[-5:]}&pass_file_suffix))):
            continue
        url = url.strip('/')
##                print(url)
        try:
            if (url.startswith('tel:')) or (url.startswith('mailto:')) or (url == 'javascript:diagnoseErrors()') or ('window.print()' in url) or (url.replace(' ','').startswith('javascript:void(')):
                continue
            elif (url.startswith('javascript:')):
                if not ((('[target="_blank"]' in css_selector) or ('[href="_blank"]' in css_selector)) and ('[href="javascript:;"]' in css_selector.lower())):
                    if i not in operate_blacklist:#黑名单
                        if operate_check_duplicates(current_url_redirection.split('/')[2].split('?',1)[0].split(':',1)[0], i):
                            task_list.append(i)
            elif check_star(current_url, url.split('/')[2].split('?',1)[0].split(':',1)[0]):
                if (len(url.split('/'))>3 and url.split('/')[3] and (url.split('/')[3][0] == '#')):
                    if url.split('/')[3][-1] != '#':
                        continue
                    elif operate_check_duplicates(current_url_redirection.split('/')[2].split('?',1)[0].split(':',1)[0], i) and (i not in operate_blacklist):#黑名单:
                        task_list.append(i)
                elif url_check_duplicates(url):
                    print(url)
                    if url not in url_blacklist:#黑名单
                        domains.append(url)
                        c.execute("INSERT INTO task(url) VALUES(?)",(url,))
        except:
            with open(file_path+'crash','a',encoding='utf-8') as f:
                f.write(url+'\n')

    print('点击特殊a标签, count:'+str(len(task_list)))
    for i in task_list:
        css_selector = (i.strip(' /<>').replace('" ','"][')+']').replace(' ','[',1).replace(']["',' "')
        try:
##                driver.execute_script("var eles = document.querySelectorAll('a');var myArray=new Array();var num=0;\
##                                        var operate="+str(operate)+";for (var i=0;i<operate.length;i++){eles[[operate[i]]].click();myArray[num++]=operate[i];};return myArray;")
##                driver.execute_script("var eles = document.querySelectorAll('a');var operate="+str(task_list)+";for (var i=0;i<operate.length;i++){eles[[operate[i]]].click();};")
            print(css_selector)
            driver.execute_script('''document.querySelector(\''''+css_selector+'''\').click()''')
        except Exception as e:
            print(str(e))
        deal_with_tabs()#处理打开的窗口
        try:
            now_url = driver_get()[1]
        except FunctionTimedOut:
            print('-----点击特殊a标签---处理打开的窗口---timeout-----')
            driver = taskkill_pid()
            now_url = ''
            break
        if now_url.strip('/') != current_url_redirection.strip('/'):
            try:
                pass_check = driver_get(current_url)
            except FunctionTimedOut:
                print('-----点击特殊a标签---处理打开的窗口---跳转刷新-----timeout-----')
                driver = taskkill_pid()
                pass_check = 1
                break
    if pass_check:
        delete_task(current_url)
        continue
            

    #执行onx函数
    sets=set()
    try:
        [[sets.add(i.get_attribute(event)) for i in driver.execute_script("var eles = document.querySelectorAll('*["+event+"]');var operate=[];for (var i=0;i<eles.length;i++){operate.push(eles[i]);};return operate;")] for event in html_dom_event]
    except Exception as e:
        print(str(e))
        delete_task(current_url)
        continue
    print('执行onx函数, count:'+str(len(sets)))
    for i in sets:
        if not i:
            continue
        elif (i.startswith('alert(')) or (i.startswith('prompt(')) or (i.startswith('confirm(')) or ('window.print()' in i):
            continue
        elif not operate_check_duplicates(current_url_redirection.split('/')[2].split('?',1)[0].split(':',1)[0], i):
            continue
        elif i in operate_blacklist:#黑名单
            continue
        print(i)
        try:
            driver.execute_script(i)
        except Exception as e:
            print(str(e))
        deal_with_tabs()#处理打开的窗口
        try:
            now_url = driver_get()[1]
        except FunctionTimedOut:
            print('-----执行onx函数-----处理打开的窗口-----timeout-----')
            driver = taskkill_pid()
            now_url = ''
            break
        if now_url.strip('/') != current_url_redirection.strip('/'):
            try:
                pass_check = driver_get(current_url)
            except FunctionTimedOut:
                print('-----执行onx函数---处理打开的窗口---跳转刷新-----timeout-----')
                driver = taskkill_pid()
                pass_check = 1
                break
    if pass_check:
        delete_task(current_url)
        continue

    #填充数据
    dicts={}
    index_str_hash_tmp=[]
    index_str_hash=[]
    for i in re.finditer('<(button|input|textarea|select|form|/form).*?>',data):
        if 'type="reset"' not in i.group():
            if dicts.__contains__(i.group()):
                dicts[i.group()]+=1
            else:
                dicts[i.group()]=1

    for key in dicts.keys():
        find_bool=0
        old_find_bool = find_bool
        for i in range(0,dicts[key]):
            if find_bool==0:
                find_bool=data[find_bool:].find(key)
                index_str_hash_tmp.append([find_bool,key])
            else:
                old_find_bool += (find_bool+1)
                find_bool=data[old_find_bool:].find(key)
                index_str_hash_tmp.append([old_find_bool+find_bool,key])
    index_str_hash_tmp = sorted(index_str_hash_tmp,key=lambda x: x[0], reverse=False)

    form_nested = 0
    key = ''
    for i in range(0,len(index_str_hash_tmp)):
        delete = False
        tag_name = index_str_hash_tmp[i][1].strip('<>').split(' ',1)[0]
        default_value = False
        if tag_name == 'form':
            if form_nested == 0:
                start = i
            form_nested += 1
        elif tag_name == '/form':
            form_nested -= 1
            if form_nested == 0:
                end = i
                delete = True
        key += index_str_hash_tmp[i][1]
        if form_nested == 0:
##                if operate_check_duplicates(current_url_redirection.split('/')[2].split('?',1)[0].split(':',1)[0], hashlib.md5(key.encode('utf-8')).hexdigest() and (key not in operate_blacklist):
            if operate_check_duplicates(current_url_redirection.split('/')[2].split('?',1)[0].split(':',1)[0], re.sub('\[value=".*?"\]','',key)) and (key not in operate_blacklist):#黑名单:
                if delete:
                    index_str_hash += index_str_hash_tmp[start:end+1]
                else:
                    index_str_hash.append(index_str_hash_tmp[i])
                key = ''

    print('填充数据, count:'+str(len(index_str_hash)))
    for i in index_str_hash:
        try:
            tag_name = i[1].strip('<>').split(' ',1)[0]
            css_selector = (i[1].strip(' /<>').replace('" ','"][')+']').replace(' ','[',1).replace(']["',' "')
            print(css_selector)
            default_value = False
            if tag_name == 'form':
                form_nested += 1
                driver.execute_script('''document.querySelector(\''''+css_selector+'''\').setAttribute("target","_blank");''')
            elif tag_name == '/form':
                form_nested -= 1
            else:
                if 'pattern="' in css_selector:
                    driver.execute_script('''document.querySelector(\''''+css_selector+'''\').removeAttribute('pattern')''')
                    css_selector = re.sub('\[pattern=".*?"\]','',css_selector)
                if 'type="hidden"' in css_selector:
                    driver.execute_script('''document.querySelector(\''''+css_selector+'''\').removeAttribute('type')''')
                    css_selector = css_selector.replace('[type="hidden"]','')
                if driver.find_element_by_css_selector(css_selector).get_attribute('hidden'):
                    driver.execute_script('''document.querySelector(\''''+css_selector+'''\').removeAttribute('hidden')''')
                    css_selector = re.sub('\[hidden.*?\]','',css_selector)
                if driver.find_element_by_css_selector(css_selector).get_attribute('disabled'):
                    driver.execute_script('''document.querySelector(\''''+css_selector+'''\').removeAttribute('disabled')''')
                    css_selector = re.sub('\[disable.*?\]','',css_selector)
                if 'style="display:none;"' in css_selector:
                    driver.execute_script('''document.querySelector(\''''+css_selector+'''\').removeAttribute('style')''')
                    css_selector = css_selector.replace('[style="display:none;"]','')
                if tag_name == 'input':
                    if ('type="radio"' in css_selector) or ('type="checkbox"' in css_selector):
                        driver.execute_script('''document.querySelector(\''''+css_selector+'''\').click()''')
                    else:
                        value = driver.find_element_by_css_selector(css_selector).get_attribute('value')
                        if ('type="file"' not in css_selector) and value:
                            driver.find_element_by_css_selector(css_selector).clear()
                            driver.find_element_by_css_selector(css_selector).send_keys(value)
                            default_value = True
                        else:
                            if ('mail' in css_selector) or ('邮箱' in css_selector):
                                driver.find_element_by_css_selector(css_selector).send_keys(email)
                            elif ('phone' in css_selector) or ('手机' in css_selector) or ('type="tel"' in css_selector):
                                driver.find_element_by_css_selector(css_selector).send_keys(phonenumber)
                            elif ('user' in css_selector) or ('usr' in css_selector) or ('用户名' in css_selector) or ('账号' in css_selector) or ('账户' in css_selector):
                                driver.find_element_by_css_selector(css_selector).send_keys(username)
                            elif ('pass' in css_selector) or ('pwd' in css_selector) or ('密码' in css_selector):
                                driver.find_element_by_css_selector(css_selector).send_keys(password)
                            elif ('type="file"' in css_selector):
                                accept = driver.find_element_by_css_selector(css_selector).get_attribute('accept')
                                #请自备
                                if ('image' in accept):
                                    driver.find_element_by_css_selector(css_selector).send_keys(data_path+'MyP3nt35t.png')
                                elif ('xls' in accept) or ('sheet' in accept) or ('excel' in accept) or ('csv' in accept):
                                    driver.find_element_by_css_selector(css_selector).send_keys(data_path+'MyP3nt35t.xlsx')
                                elif ('zip' in accept):
                                    driver.find_element_by_css_selector(css_selector).send_keys(data_path+'MyP3nt35t.zip')
                                elif ('json' in accept):
                                    driver.find_element_by_css_selector(css_selector).send_keys(data_path+'MyP3nt35t.json')
                                elif ('html' in accept):
                                    driver.find_element_by_css_selector(css_selector).send_keys(data_path+'MyP3nt35t.html')
                                else:
                                    driver.find_element_by_css_selector(css_selector).send_keys(data_path+'MyP3nt35t.txt')
                                #。。。
                            else:
                                driver.find_element_by_css_selector(css_selector).send_keys(other_text)
                            if ('type="file"' not in css_selector) and ((not form_nested) or (form_nested and not default_value)):
                                driver.find_element_by_css_selector(css_selector).send_keys(Keys.ENTER)
                    if default_value and (not cookie):
                        driver.delete_all_cookies()
                        default_value = False
                elif tag_name == 'button':
                    driver.execute_script('''document.querySelector(\''''+css_selector+'''\').click()''')
                elif tag_name == 'textarea':
                    driver.find_element_by_css_selector(css_selector).send_keys(textarea)
                elif tag_name == 'select':
                    select = Select(driver.find_element_by_css_selector(css_selector))
                    if len(select.options) > 1:
                        select.select_by_index(1)
                    elif len(select.options) == 1:
                        select.select_by_index(0)
        except Exception as e:
            print(str(e))
        deal_with_tabs()#处理打开的窗口
        try:
            now_url = driver_get()[1]
        except FunctionTimedOut:
            print('-----填充数据---处理打开的窗口-----timeout-----')
            driver = taskkill_pid()
            now_url = ''
            break
        if now_url.strip('/') != current_url_redirection.strip('/'):
            try:
                pass_check = driver_get(current_url)
            except FunctionTimedOut:
                print('-----填充数据---处理打开的窗口---跳转刷新-----timeout-----')
                driver = taskkill_pid()
                pass_check = 1
                break

    delete_task(current_url)
            
c.close()
conn.close()
