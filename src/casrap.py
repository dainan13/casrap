#!/usr/bin/env python3

import os
import os.path
import time
import json
import pickle
import urllib
import urllib.parse
import datetime
import re
import random

import asyncio

import uuid 
import hashlib

import user_agents

import jasorm
#import smartsnow


#OK = b"+OK\r\n"
#ERROR_INVALID_COMMAND = b"-Invalid Command\r\n"

from hashids import Hashids
from redislite import Redis

class App(object):
    
    def __init__( self, configfilepath ):
        
        #self.sitename = sitename
        self.configfilepath = configfilepath
        self.configmodified = None
        
        self.redis = Redis()
        
        self.castag = int(time.time())
        
        self.reload()
        
        self.machine_id = 1
        self.cnt = random.randint(10000,99999)
        
        self.db = jasorm.Jasorm(
            self.system['tracking']['type'],
            self.system['tracking']['config'],
        )
        
        return
    
    def counter(self):
        self.cnt += 1
        return self.cnt
    
    def timer(self):
        return int(time.time())-946656000
    
    def load_system( self, config ):
        
        #"code": "CASRAP",
        #"key": "fb5a2022-af34-4d4f-844c-e8a260c8da85",
        #"create_time": "2022-10-19 15:55:55"
        
        assert "code" in config and type(config["code"]) == str, ""
        assert "key" in config and type(config["key"]) == str, ""
        assert "create_time" in config and type(config["create_time"]) == str, ""
        
        self.system = config
        
        return
        
    def load_platform( self, config ):
        
        #"name":"CASRAP测试",
        #"code":"CASRAP",
        #"key":"277b70ba-a316-43b7-91d4-b3620dcf73f1",
        #
        #"urlroot":"https://www.casrap.com",
        #
        #"apphome":"portal",
        #"appindex":"portal",
        #
        #"urlapp":"https://www.casrap.com/console/{appcode}/",
        #
        #"urlapi":"https://api.casrap.com/",
        #"urlucs":"https://ucs.casrap.com/",
        #
        #"authtype":"cookie",
        #"passport":".casrap.com",
        #"singleton":true,
        #
        #"max_period":120,
        #"renewal_period":10
            
        for plat_code, plat in config.items() :
            
            assert "name" in plat and type(plat["name"]) == str, "parse error /platform/name"
            #assert "code" in config and type(config["code"]) == str, "parse error /platform/code"
            #assert "key" in plat and type(plat["key"]) == str, "parse error /platform/key"
            
            assert "urlroot" in plat and type(plat["urlroot"]) == str, "parse error /platform/urlroot"
            assert plat["urlroot"].startswith("https://") or plat["urlroot"].startswith("http://"), "parse error /platform/urlroot"
            
            #if config["urlroot"].endswith('/')
            
            assert "apphome" in plat and type(plat["apphome"]) == str, "parse error /platform/apphome"
            assert "appindex" in plat and type(plat["appindex"]) == str, "parse error /platform/appindex"
            
            assert "urlapp" in plat and type(plat["urlapp"]) == str, "parse error /platform/urlapp"
            
            assert "urlapi" in plat and type(plat["urlapi"]) == str, "parse error /platform/urlapi"
            assert "urlucs" in plat and type(plat["urlucs"]) == str, "parse error /platform/urlucs"
            
            assert "authtype" in plat and type(plat["authtype"]) == str, "parse error /platform/authtype"
            assert "passport" in plat and type(plat["passport"]) == str, "parse error /platform/passport"
            
            assert "singleton" in plat and type(plat["singleton"]) == bool, "parse error /platform/singleton"

            assert "max_period" in plat and type(plat["max_period"]) == int, "parse error /platform/max_period"
            assert "renewal_period" in plat and type(plat["renewal_period"]) == int, "parse error /platform/renewal_period"

            plat['idhash'] = Hashids(
                salt=self.system['key']+plat['code'], 
                min_length=16, 
                alphabet='abcdefghijklmnopqrstuvwxyz0123456789'
            )
            
            plat.setdefault('applogin',None)
            
            plat['urlapp_path'] = '/console/' #urllib.parse.urlparse(plat['urlapi']).path
            plat['urlapi_path'] = urllib.parse.urlparse(plat['urlapi']).path
            plat['urlucs_path'] = urllib.parse.urlparse(plat['urlucs']).path
            
            plat['default_close'] = plat.get('default_close',False)
            plat['default_appclose'] = plat.get('default_appclose',None)
            
            oldplat = self.platforms.get(plat_code,{})
            
            plat['close'] = plat.get('close',oldplat.get('close',plat['default_close']))
            plat['appclose'] = plat.get('appclose',oldplat.get('appclose',plat['default_appclose']))
            
            assert plat['code'] == plat_code
            
            self.platforms[plat_code] = plat
            
        return
    
    def load_service( self, config ):

        for srv_code, service in config.items():
            
            assert "backends" in service and type(service["backends"]) == list, "parse error /service/backends"
            assert all([ type(b) == str for b in service['backends'] ]), "parse error /service/backends"
            
            assert service['code'] == srv_code
            
            self.services[srv_code] = service
        
        return
    
    def load_application( self, config ):
        
        for app_code, app in config.items():
            
            assert app['code'] == app_code
            
            self.apps[app_code] = app
        
        return 
    
    def load_role( self, config ):
        
        for role_code, role in config.items():
            
            assert role['code'] == role_code
            
            self.roles[role_code] = role
        
        return
    
    def load_api( self, config ):
        
        #for api_code, apicfg in config.items():
        #    self.redis.hset( 'apiacl', api_code, pickle.dumps(set(apicfg['roles'])) )
        #    #print('-',api['code'], pickle.dumps(set(api['roles'])), set(apicfg['roles']))
        
        for api, allow in config.items():
            
            self.api[api] = set(allow)
            
        return
        
    def load_apimap( self, config ):
        
        #for api_code, apicfg in config.items():
        #    self.redis.hset( 'apiacl', api_code, pickle.dumps(set(apicfg['roles'])) )
        #    #print('-',api['code'], pickle.dumps(set(api['roles'])), set(apicfg['roles']))
        
        self.apimap = config.copy()
        
        return
    
    def load_menu( self, config ):
        
        for menu_code, menu in config.items() :
            
            self.menu[menu_code] = menu
            menu['allow'] = set(menu['allow'])
        
        return
    
    def reload( self ):
        
        _modified = os.path.getmtime(self.configfilepath)
        
        #with open('%s/config.json' % self.sitename, 'r') as fp :
        #    config = json.load(fp)
        
        if self.configmodified == _modified :
            return
        
        try :
            with open(self.configfilepath, 'r') as fp :
                config = json.load(fp)
        except :
            return
        
        self.configmodified = _modified
        self.castag += 1
        
        print('------------------------------ config reloaded...')
        
        self.load_system( config['system'] )
        
        self.platforms = { k:v for k, v in getattr(self,"platforms",{}).items() if k in config['platform'] }
        self.load_platform( config['platform'] )
        
        self.services = {}
        self.load_service( config['service'] )
        
        self.apps = {}
        self.load_application( config['application'] )
        
        self.roles = {}
        self.load_role( config['role'] )
        
        self.api = {}
        self.load_api( config['api'] )
        
        self.load_apimap( config.get('apimap',{}) )
        
        self.menu = {}
        self.load_menu( config['menu'] )
        
        return
    
    def check_session( self, platcode, session_code, plat ):
        
        curtime = int(time.time())
        
        if not session_code :
            return False
        
        user_id, session_id = plat['idhash'].decode(session_code)
        
        session_key = 'ssn_{}_{}'.format(platcode,session_id)
        session_expires = self.redis.hget( session_key, "expires" )
        session_expires = int(session_expires) if session_expires else 0
        
        if session_expires < curtime :
            return False
            
        if plat :
            
            logintime = self.redis.hget(session_key,'logintime')
            logintime = int(logintime) if logintime else curtime
            
            self.redis.hset( session_key, "expires", min(curtime+plat["renewal_period"]*60, logintime+plat["max_period"]*60) )
            #self.redis.expire( session_key, self.platforms[platcode]['idhash'] )
        
        return True
    
    
    def get_client( self, client_ip, uahash, ja3hash, ua, ja3 ):
        
        uax = user_agents.parse(ua)
        
        uas = [
            uax.os.family or "",
            uax.os.version_string or "",
            uax.browser.family or "",
            #uax.browser.version_string or "",
            hex(int(time.time()))[2:],
            "x1",
        ]
        
        client_sn = re.sub(r"[^a-zA-Z0-9]","","".join(uas))
        
        self.db.uac_clientinfo.append( {
            'client_sn':client_sn,
            'client_ip':client_ip,
            'uahash':uahash,
            'ja3hash':ja3hash,
            'ua':ua,
            'ja3':ja3,
            'created_at':datetime.datetime.now()
        } )
        
        return client_sn
    
    def cmd__sysinfo( self, castag ):
        
        syscode = self.system['code']
        
        #print( 'SYSTEM', syscode, datetime.datetime.now() )
        self.reload()
        
        r = {
            '{}$castag'.format(syscode): str(self.castag)
        }
        
        if str(self.castag) != castag :
            
            for p, pi in self.platforms.items() :
                
                r['{}/{}$appindex'.format(syscode,p)] = pi['appindex']
                r['{}/{}$apphome'.format(syscode,p)] = pi['apphome']
                r['{}/{}$appclose'.format(syscode,p)] = pi['appclose']
                
                r['{}/{}$close'.format(syscode,p)] = pi['close']
                
                for appc, appi in self.apps.items():
                    if p in appi['allow'] :
                        r['{}/{}/{}'.format(syscode, p, appc)] = True
        
        return 200, r, {}
        
        #return 200, {
        #    p: {
        #        "name": pi['name'],
        #        "appindex": pi['appindex'],
        #        "apphome": pi['apphome'],
        #        "applist": { appc:True for appc, appi in self.apps.items() if p in appi['allow'] },
        #        "close": pi['close'],
        #        "appclose": pi['appclose']
        #    }
        #    for p, pi in  self.platforms.items()
        #}, {}
    
    def cmd__appinfo( self, platcode, url, session_code, client_sn, client_ip, ua, ja3, ja3hash, appcode=None ):
        
        session_code = session_code or None
        
        ua = ua or None
        ja3 = ja3 or None
        uahash = hashlib.md5(ua.encode('ascii')).hexdigest() if ua else None
        ja3hash = ja3hash if ja3 else None
        
        client_sn = client_sn or self.get_client( client_ip, uahash, ja3hash, ua, ja3 )
        
        plat = self.platforms[platcode]
        
        islogin = bool(session_code)
        
        if islogin :
            user_id, session_id = plat['idhash'].decode(session_code)
        else :
            user_id, session_id = None, None
        
        if appcode :
            approot = url
        elif url.startswith(plat['urlapp_path']) :
            appcode = url.split('/')[2].lower()
            approot = plat["urlapp"].format(appcode = appcode.lower())
        else :
            appcode = plat["appindex"]
            approot = plat["urlroot"]+'/'
            
        apphome = (plat["urlroot"]+'/') if plat["apphome"] in (None, "", plat["appindex"]) else plat["urlapp"].format(appcode = plat["apphome"])
        applogin = (plat["urlroot"]+'/') if plat["applogin"] in (None, "", plat["appindex"]) else plat["urlapp"].format(appcode = plat["applogin"])
        
        app = self.apps.get(appcode, None)
        if app is None and appcode.isdigit() and '$' and self.apps:
            
            xapp = self.apps['$']
            app = json.load( urllib.request.urlopen(xapp['req'].format(appcode) ) )
            app = { 'code':app['result']['appcode'], 'name':app['result']['appname'], 'allow':[] }
        
        if app is None or (platcode not in self.system['debug'] and platcode not in app['allow']) :
            
            return 403, {
                "casrap-cookie-client": client_sn
            }, {
            
                "platcode": plat["code"], # 平台的注册名（KEY）
                "platname": plat["name"], # 平台的注册名（中文）
                
                "userapi" : plat["userapi"],
                
                "urlindex": plat["urlroot"], # 平台的首页位置（URL）
                "urllogin": applogin, # 平台的登录页位置（URL）
                "urlhome": apphome, # 平台的用户个人主页位置（URL）
                
                "appcode": ( app['code'] if app else None ), # 前端项目的注册名（KEY）
                "appname": None, # 前端项目的注册名（中文）
                
                "appinstance": None
            }
        
        ins_sn = plat['idhash'].encode( 
            (session_id or 0), 
            (user_id or 0), 
            self.machine_id, 
            self.timer(),
            self.counter()
        )
        appins = "{}_{}_{}".format( platcode, app["code"].replace('_',''), ins_sn )
        
        self.db.uac_appinstance.append( {
            
            "instance_sn": appins,
            "platform": platcode,
            "app_code": appcode,
            "session_id": session_id,
            "user_id": user_id,
            "client_sn": client_sn,
            "create_time": datetime.datetime.now(),
            
        } )
        
        return 200, {
            "casrap-cookie-client": client_sn
        }, {
        
            "platcode": plat["code"], # 平台的注册名（KEY）
            "platname": plat["name"], # 平台的注册名（中文）
            
            "userapi" : plat["userapi"],
            
            "urlindex": plat["urlroot"], # 平台的首页位置（URL）
            "urllogin": applogin, # 平台的登录页位置（URL）
            "urlhome": apphome, # 平台的用户个人主页位置（URL）
            "urlapp": approot, # 本应用在平台的位置根（URL）
            
            "urlapi": plat["urlapi"], # API请求的位置根（URL）
            "urlucs": plat["urlucs"], # 用户存储资源的位置根（URL）
            
            "appcode": app["code"], # 前端项目的注册名（KEY）
            "appname": app["name"], # 前端项目的注册名（中文）
            
            "appinstance": appins
        }
    
    def cmd__aclapi( self, platcode, url, session_code, client_sn, remote_ip ):
        
        curtime = int(time.time())
        
        plat = self.platforms.get(platcode, None)
        
        assert plat, 'PLATFORM NOT FOUND'
        assert url.startswith( plat['urlapi_path'] ), 'API URL PREFIX NOT MATCH PLATFORM'
        
        api = url[len(plat['urlapi_path']):].strip('/')
        apimod = api.split('/')[0]
        
        if apimod in ('public', 'common') :
            apimod = api.split('/')[1]
            
        if apimod == 'inner' :
            assert "API URL PREFIX CAN NOT AS KEYWORD INNER."
        
        apicode = '/'+api
        apikey = platcode+':'+apicode
        
        
        userroles = {'$anyone'}
        session_key = None
        session_id = None
        
        user_id = None
        user_name = None
        account = None
        
        islogin = bool(session_code)
        
        if islogin :
            
            user_id, session_id = plat['idhash'].decode(session_code)
            
            session_key = 'ssn_{}_{}'.format(platcode,session_id)
            session_expires = self.redis.hget( session_key, "expires" )
            session_expires = int(session_expires) if session_expires else 0
            
            if session_expires < curtime :
                islogin = False
                session_key = None

        if islogin:
            
            #user_name = self.redis.hget(session_key,'user_name')
            #account = self.redis.hget(session_key,'account')
            
            userroles |= pickle.loads( self.redis.hget('userroles',user_id) or b'\x80\x04\x8f\x94.' )
            
            logintime = self.redis.hget(session_key,'logintime')
            logintime = int(logintime) if logintime else curtime
            self.redis.hset( session_key, "expires", min(curtime+plat["renewal_period"]*60, logintime+plat["max_period"]*60) )
            #self.redis.expire( session_key, self.platforms[platcode]['idhash'] )
        
        else :
            
            user_id, session_id = 0, 0
            session_expires = 0
        
        if plat['close'] == True :
            userroles = {'$close'}
        
        #apiroles = pickle.loads( self.redis.hget('apiacl',apicode) or b'\x80\x04\x8f\x94.' )
        apiroles = self.api.get(apikey,set())
        
        authrole = apiroles&userroles
        authpass = bool( authrole )
        
        #if islogin and '$debug' in userroles :
        if platcode in self.system["debug"]:
            authpass = True
        
        trace_sn = 'URQ_{}_{}'.format( platcode, plat['idhash'].encode(
            user_id ,
            session_id ,
            self.machine_id,
            self.timer(),
            self.counter(),
        ) )
        
        print('aclapi', authpass, islogin, user_id, session_id, session_expires)
        
        return (200 if authpass else 400), {
            "authpass": authpass,
            "authrole": ','.join( sorted(list(authrole)) ),
            "trace_sn": trace_sn,
            "client_sn": client_sn,
            "api": apicode,
            "uri": self.apimap.get(apicode,None),
        }, {}
    
    def cmd__callapi( self, url, trace_sn, client_sn, client_ip, proto ):
        
        prefix, platcode, trace_id = trace_sn.split('_')
        assert prefix == 'URQ', "NOW ONLY SUPPORT URQ"
        plat = self.platforms[platcode]
        user_id, session_id, machine_id, call_at, call_id = plat['idhash'].decode(trace_id)
        
        user_id = None if user_id == 0 else user_id
        session_id = None if session_id == 0 else session_id
        
        islogin = bool( session_id )
        
        if islogin :
            
            session_key = 'ssn_{}_{}'.format(platcode,session_id)
            user_name = self.redis.hget(session_key,'user_name').decode('utf-8')
            account = self.redis.hget(session_key,'user_account').decode('utf-8')
            
        else :
            
            session_key = None
            user_name = None
            account = None
        
        apicode = '/'+url.strip('/') #url.strip('/').replace('/','__')
        apimod = url.strip('/').split('/')[0]
        
        if apimod in ('public', 'common', 'inner') :
            apimod = url.strip('/').split('/')[1]
            
        apisrv = self.services.get(apimod, None) or self.services.get('$', None)
        apiver = apisrv.get('apiver', None) if apisrv else 2023
        apiaddr = random.choice(apisrv['backends']) if apisrv and apisrv.get('backends') else None
        apiaddr = 'local' if apimod == 'casrap' else apiaddr
        
        srvvar = apisrv.get('var', {}) if apisrv else {}
        srvvar = srvvar.get(platcode) or srvvar.get('*') or {}
        
        print(srvvar)
        
        if apiaddr == None :
            return 503, {
                "client_sn": client_sn,
                "client_ip": client_ip,
                "trace_sn": trace_sn,
                "proto": proto,
            }, {}
        
        if apiver == 2018 :
            
            session = {
                "uid": user_id,
                "sid": None,
                "platform": platcode,
                "platname": plat['name'],
                "uname": user_name,
                "account": account,
                "trace_sn": trace_sn,
                "has_logged_in": islogin,
            }
        else :
            session = {
                "login": islogin,
                "trace_sn": trace_sn,
                "platform": platcode,
                "client_sn": client_sn,
                "user_id": user_id,
                "user_name": user_name,
                "user_account": account,
                "client_ip": client_ip,
                "proto": proto,
            }
            
            session.update( srvvar )
        
        passport = {
            "api_addr": apiaddr,
            "api_mod": apimod,
            "api_code": apicode,
            "api_ver": apiver,
            "client_sn": client_sn,
            "client_ip": client_ip,
            "trace_sn": trace_sn,
            "proto": proto,
        }
        
        print('callapi', passport)
        
        return 200, passport, session
    
    # def cmd__basicauth( self, url, header, client_ip, proto ):
        
    #     account, password = base64.b64decode(header).split(b':',1)
        
    #     account = account.decode('ascii')
        
    #     acc_info = self.db.user_basic.where(account=account).select()
        
    #     if len(acc_info) == 0:
    #         authpass = False
    #     else :
    #         acc_info = acc_info[0]
    #         authpass = bool( hashlib.sha1(password) == acc_info['password'] )
        
    #     return (200 if authpass else 400), {
    #         "authpass": authpass,
    #         "authrole": '',
    #         "trace_sn": trace_sn,
    #         "client_sn": client_sn,
    #         "api": apicode,
    #         "uri": url,
    #     }, {}
    
    def cmd__logapi( self, trace_sn, api_code, method, proto, status, client_sn, client_ip, uahash, ja3hash, used_time ):
        
        prefix, platcode, trace_id = trace_sn.split('_')
        assert prefix == 'URQ', "NOW ONLY SUPPORT URQ"
        plat = self.platforms[platcode]
        user_id, session_id, machine_id, call_at, call_id = plat['idhash'].decode(trace_id)
        
        self.db.uac_accesslog.append( {
            "trace_sn": trace_sn,
            "platform": platcode,
            "app_code": None,
            "app_sid": None,
            "session_id": session_id,
            "user_id": user_id,
            "api_code": api_code,
            "method": method,
            "proto": proto,
            "client_sn": client_sn,
            "client_ip": client_ip,
            "uahash": uahash,
            "ja3hash": ja3hash,
            "request_at": datetime.datetime.now(),
            "status": status,
            "used_time": used_time,
            "gateserver": 1,
        } )
        
        return 200, {}, {}
    
    def cmd__aclucs( self, platcode, url, action, session_code, client_sn, remote_ip, ucsroot ):
        
        curtime = int(time.time())
        
        plat = self.platforms.get(platcode, None)
        
        assert plat, 'PLATFORM NOT FOUND'
        assert url.startswith( plat['urlapi_path'] ), 'API URL PREFIX NOT MATCH PLATFORM'
        
        ucs = url[len(plat['urlucs_path']):].strip('/')
        ucsbucket, ucsfile = ucs.split('/')[:2]
        
        userroles = {'$anyone'}
        session_key = None
        session_id = None
        
        islogin = bool(session_code)
        
        authpass = False
        
        if islogin :
            
            user_id, session_id = plat['idhash'].decode(session_code)
            
            session_key = 'ssn_{}_{}'.format(platcode,session_id)
            session_expires = self.redis.hget( session_key, "expires" )
            session_expires = int(session_expires) if session_expires else 0
            
            if session_expires < curtime :
                islogin = False
                session_key = None

        if islogin :
            
            sucs_key = 'ucss_{}_{}'.format(platcode,session_id)
            actions = self.redis.hget(sucs_key, ucsbucket+'/'+ucsfile)
            actions = pickle.loads( actions or b'\x80\x04\x8f\x94.' )
            
            if action in actions :
                authpass = True
            
        if not authpass :
            
            if islogin :
                userroles |= pickle.loads( self.redis.hget('userroles',user_id) or b'\x80\x04\x8f\x94.' )
            
            rucs_key = 'ucsr_{}_{}'.format(platcode,bucket)
            
            actions = pickle.loads( self.redis.hmget(rucs_key,bucket) or b'\x80\x04\x8f\x94.' )
            
            role:actions
            
        trace_sn = 'UCS_{}_{}'.format( platcode, plat['idhash'].encode(
            user_id,
            session_id,
            1,
            self.cnt,
        ) )
        
        self.cnt += 1
        
        return {
            "authpass": authpass,
            "authrole": ','.join( sorted(list(authrole)) ),
            "trace_sn": trace_sn,
            "api": '/'+api,
        }
        
        return
        
    def cmd__callucs( self, url, trace_sn, client_sn, client_ip, proto ):
        
        return {
            "trace_sn": trace_sn,
        }
    
    def cmd__casrap( self, trace_sn, api, kwargs ):
        
        print('<<', trace_sn, api, kwargs )
        
        prefix, platcode, trace_id = trace_sn.split('_')
        
        if prefix == 'URQ':
            plat = self.platforms[platcode]
            user_id, session_id, machine_id, call_at, call_id = plat['idhash'].decode(trace_id)
            
            session = {
                'platcode': platcode,
                #'platform': platform,
                'user_id': user_id,
                'session_id': session_id,
                'machine_id': machine_id,
                'call_id': call_id,
            }
            
        elif prefix == 'CMD':
            session = {
                'platcode': None,
                'user_id': None,
                'session_id': None,
                'machine_id': None,
                'call_id': None,
            }
            
        else :
            assert False, "NOT SUPPORT TRACE FORMAT, NOT URQ or CMD"
        
        kwargs = json.loads(kwargs)
        
        if not api.startswith('/casrap/'):
            return
            
        func = getattr(self, api.strip('/').lower().replace('/','__'), None)
        
        if func is None :
            return ( 403, {}, {"status":404, "error":"api not found."} )
        
        try :
            r = func(session,**kwargs)
            st, hd, data = r
            if st <= 299 :
                r = (st, hd, {'status':st, "result":data})
            else :
                r = (st, hd, {'status':st, "error":data})
        except :
            import traceback
            traceback.print_exc()
            r = ( 500, {}, {
                "status": 500,
                "error": "internal server error.",
            } )
        
        print('>>',r)
        
        return r
    
    def casrap__set_session( self, _, platcode, user_id, user_name, user_account, session_id ):
        
        curtime = int(time.time())
        
        plat = self.platforms[platcode]
        
        session_code = plat['idhash'].encode( user_id, session_id )
        session_key = 'ssn_{}_{}'.format( platcode, session_id )
        self.redis.hset( session_key, "logintime", curtime )
        self.redis.hset( session_key, "expires", curtime+plat["renewal_period"]*60 )
        self.redis.hset( session_key, "user_id", user_id )
        self.redis.hset( session_key, "user_name", user_name )
        self.redis.hset( session_key, "user_account", user_account )
        
        return 200, {}, {
            "authtype": "cookie",
            "session_code" : session_code,
        }
    
    def casrap__set_userrole( self, __session, user_id, roles ):
        
        if user_id == None :
            user_id = __session['user_id']
        
        roles = pickle.dumps(set(roles))
        self.redis.hset('userroles', user_id, roles)
        
        return 200, {}, True
    
    def casrap__get_userrole( self, __session, user_id ):
        
        if user_id == None :
            user_id = __session['user_id']
        
        roles = self.redis.hget('userroles', user_id)
        roles = pickle.loads(roles or b'\x80\x04\x8f\x94.')
        
        return 200, {}, {
            'roles' : list(roles)
        }
    
    def casrap__test_acl( self, __session, user_id, platform_key, api ):
        
        if user_id == None :
            user_id = __session['user_id']
        
        userroles = {'$anyone'}
        userroles |= pickle.loads( self.redis.hget('userroles',user_id) or b'\x80\x04\x8f\x94.' )
        
        apikey = platform_key+':'+api
        
        apiroles = self.api.get(apikey,set())

        authrole = apiroles&userroles
        authpass = bool( authrole )

        return 200, {}, {
            'userroles': list(userroles),
            'apiroles': list(apiroles),
            'authrole': apiroles&userroles,
            'authpass': bool( authrole )
        }
    
    def casrap__get_menu( self, __session, root, depth, appcode=None ):
        
        userroles = {'$anyone'}
        if __session['user_id'] :
            userroles |= pickle.loads( self.redis.hget('userroles',__session['user_id']) or b'\x80\x04\x8f\x94.' )
        
        urcodes = { __session['platcode']+":"+ur for ur in userroles }
        
        plat = self.platforms[__session['platcode']]
        
        rootm = self._get_menu(root, depth, plat, urcodes, appcode)
        
        return 200, {
        }, {
            "root":root,
            "depth":depth,
            "menus":rootm['children'] if rootm else []
        }
    
    def _get_menu( self, root, depth, plat, urcodes, anchorapp ):
        
        if depth < 0 :
            return None
        
        rootm = self.menu.get(root, None)
        
        if not rootm :
            return None
        
        if root != "" :
            allow = rootm['allow'] & urcodes 
            if not allow :
                print('xxxxxx', root, depth, rootm['allow'], urcodes )
                return None
        else :
            allow = {'$anyone'}
        
        #print('>>>>>>', root, depth, rootm['allow'], allow)
        
        rootm = rootm.copy()
        
        rootm['allow'] = list(allow)
        
        children = [ self._get_menu(m, depth-1, plat, urcodes, anchorapp ) for m in rootm['children'] ]
        rootm['children'] = [ child for child in children if child ]
        
        if not rootm['url']:
            rootm['url'] = None
            
        elif rootm['url'].startswith('//$'): # //$login/xxx
            app, path = rootm['url'][:3].split('/',1)
            if app == plat['appindex'] :
                rootm['url'] = plat["urlroot"].rstrip('/') + '/' + path
            else :
                rootm['url'] = plat["urlapp"].format(appcode=app.lower()) + path
            
        elif rootm['url'].startswith('//'): # //xxx/
            rootm['url'] = plat["urlroot"].rstrip('/') + '/' + rootm['url'][2:]
            
        elif rootm['url'].startswith('/#') and rootm['app'] == anchorapp: # /#
            rootm['url'] = rootm['url'][1:]
            
        elif rootm['url'].startswith('/'): # /
            if rootm['app'] == plat['appindex'] :
                rootm['url'] = plat["urlroot"].rstrip('/') + '/' + rootm['url'][1:]
            else :
                rootm['url'] = plat["urlapp"].format(appcode=rootm['app'].lower()) + rootm['url'][1:]
            
        elif rootm['url'].startswith('api://'):
            rootm['url'] = plat['urlapi_path'] + rootm['url'][6:]
            
        else :
            pass
        
        return rootm
    
    def casrap__debug_session_info( self, __session ):
        
        return 200, {}, {
            "login":True,
            "user_name":"测试账号",
            "user_account":"zyhxjh",
            "client_ip":None,
        }
    
    def casrap__get_platforms( self, __session ):
        
        plats = [
            {
                'code': p['code'],
                'name': p['name'],
                'urlroot': p['urlroot'],
                'close': p['close'],
                'appclose': p['appclose']
            } for p in self.platforms.values()
        ]
        
        return 200, {}, {
            'platforms':plats,
        }
        
    def casrap__close_platform( self, __session, platcode, close, appclose=None ):
        
        vd = {True:True, False:False, "true":True, "false":False, 1: True, 0: False}
        assert close in vd, 'incorrect value'
        
        assert platcode in self.platforms, 'platform not found'
        
        self.castag += 1
        
        plat = self.platforms[platcode]
        plat['close'] = vd[close]
        plat['appclose'] = appclose or None
        
        return 200, {}, {
            'code': plat['code'],
            'name': plat['name'],
            'close': plat['close'],
            'appclose': plat['appclose']
        }
    
    async def process_command(self, writer, command, *args):
        
        try :
            command = command.decode('utf-8')
            command = command.lower()
        except :
            writer.write(b"-Invalid Command\r\n")
            await writer.drain()
            return True
        
        if command == "quit" :
            writer.write(b"+OK\r\n")
            await writer.drain()
            return True
        
        if command != 'sysinfo':
            print(">", command, args)
        
        func = getattr(self, "cmd__"+command.lower(), None)
        
        if func is None :
            writer.write(b"-Invalid Command\r\n")
            await writer.drain()
            return True
            
        try :
            args = dict( tuple(a.decode('utf-8').split("=",1)) for a in args )
        except :
            import traceback
            traceback.print_exc()
            writer.write(b"-Argument Error\r\n")
            await writer.drain()
            return True
            
        try :
            status, header, data = func( **args )
            status = str(status).encode('ascii')
            header = json.dumps(header, ensure_ascii=False).encode("utf-8")
            data = json.dumps(data, ensure_ascii=True).encode("utf-8")
        except :
            import traceback
            traceback.print_exc()
            writer.write(b"-Server Error\r\n")
            await writer.drain()
            return True
            
        if command != 'sysinfo':
            print("<", status, header, data)
        
        writer.write(b"*3\r\n")
        writer.write(b"$%d\r\n%s\r\n" % (len(status),status))
        writer.write(b"$%d\r\n%s\r\n" % (len(header),header))
        writer.write(b"$%d\r\n%s\r\n" % (len(data),data))
        
        await writer.drain()
        
        return False

    async def handle_connection(self, reader, writer):
        
        while True:
            
            try :
                data = await reader.readobj()
            except ConnectionResetError as e:
                return
            
            if not data:
                break
                
            should_break = await self.process_command(writer, data[0], *data[1:])
            if should_break:
                break
            
        writer.close()




import hiredis

MAX_CHUNK_SIZE = 65536


class StreamReader(asyncio.StreamReader):
    """
    Override the official StreamReader to address the
    following issue: http://bugs.python.org/issue30861

    Also it leverages to get rid of the dobule buffer and
    get rid of one coroutine step. Data flows from the buffer
    to the Redis parser directly.
    """
    _parser = None

    def set_parser(self, parser):
        self._parser = parser
        if self._buffer:
            self._parser.feed(self._buffer)
            del self._buffer[:]

    def feed_data(self, data):
        assert not self._eof, 'feed_data after feed_eof'

        if not data:
            return
        if self._parser is None:
            # XXX: hopefully it's only a small error message
            self._buffer.extend(data)
            return
        self._parser.feed(data)
        self._wakeup_waiter()

        # TODO: implement pause the read. Its needed
        #       expose the len of the buffer from hiredis
        #       to make it possible.

    async def readobj(self):
        """
        Return a parsed Redis object or an exception
        when something wrong happened.
        """
        assert self._parser is not None, "set_parser must be called"
        while True:
            obj = self._parser.gets()

            if obj is not False:
                # TODO: implement resume the read

                # Return any valid object and the Nil->None
                # case. When its False there is nothing there
                # to be parsed and we have to wait for more data.
                return obj

            if self._exception:
                raise self._exception

            if self._eof:
                break

            await self._wait_for_data('readobj')
        # NOTE: after break we return None which must be handled as b''

    async def _read_not_allowed(self, *args, **kwargs):
        raise RuntimeError('Use readobj')

    read = _read_not_allowed
    readline = _read_not_allowed
    readuntil = _read_not_allowed
    readexactly = _read_not_allowed


def run( conf_file ):
    
    app = App( conf_file )
    
    loop = asyncio.get_event_loop()

    def factory():
        reader = StreamReader(limit=MAX_CHUNK_SIZE, loop=loop)
        reader.set_parser(hiredis.Reader())
        return asyncio.streams.StreamReaderProtocol(reader, app.handle_connection, loop=loop)
    print(app.system,'............')
    if 'port' in app.system :
        host = app.system.get('host',"127.0.0.1")
        port = int(app.system['port'])
        print( 'listen', host, ':', port )
        coro = loop.create_server(factory, host, port)
    else :
        sockfile = app.system.get('sock', app.system["code"]+'.sock')
        sockfile = sockfile if os.path.isabs(sockfile) else os.path.join('/var/lib/casrap/',sockfile)
        print( 'listen', sockfile )
        coro = loop.create_unix_server(factory, sockfile)
        
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    
    return


if __name__ == "__main__":
    
    import sys
    import getopt
    
    optlist, args = getopt.getopt(sys.argv[1:], 'c:')
    optdict = dict(optlist)
    argcmd = args.pop(0) if args else None

    
    if argcmd :
        conf_file = optdict.get('-c',None) or "/etc/casrap/config.json"
        assert os.path.exists(conf_file) and os.path.isfile(conf_file), 'conf file not found.'
        
    if argcmd == 'run':
        run(conf_file)
    else :
        print('casrap [-c configfile] run')


