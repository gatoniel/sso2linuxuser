# -*- coding: utf-8 -*-
"""
Created on Thu Apr  9 17:20:43 2020

@author: niklas
"""

import re
import os
import pwd
import secrets
import argparse
import logging
from logging.handlers import SysLogHandle
from subprocess import Popen, PIPE
from multiprocessing import Process, Pipe

import pamela

import tornado.ioloop
import tornado.web
import tornado.httpserver
import tornado.httputil
from tornado.web import url

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

session = {}

class Application(tornado.web.Application):
    def __init__(
            self, cookie_secret, saml_path, logger, debug=False,
            base_url="/shibboleth",
            https_reverse_proxy=True,
            remote_login="/jupyterhub"
            ):
        BASE_DIR = os.path.dirname(__file__)
        TEMPLATE_PATH = os.path.join(BASE_DIR, 'templates')
        logger.debug("TEMPLATE PATH: %s", TEMPLATE_PATH)
        
        login_url = r"/sso"
        handlers_tmp = [
            (r"/", IndexHandler, "index"),
            (login_url, SSOHandler, "login_sso"),
            (r"/acs", ACSHandler, "acs"),
            (r"/formular", FormularHandler, "formular"),
            (r"/create", CreateHandler, "create"),
            (r"/metadata", MetadataHandler, "saml_metadata"),
            (r"/logout", LogoutHandler, "logout"),
        ]
        handlers = [
                url(base_url+x0, x1, name=x2) for (x0,x1,x2) in handlers_tmp
                ]        
        settings = {
            "template_path": TEMPLATE_PATH,
            "autorealod": True,
            "debug": debug,
            "xsrf_cookies": True,
            "login_url": base_url+login_url,
            
            # our own settings come here
            "logger": logger,
            "saml_path": saml_path,
            "https_reverse_proxy": https_reverse_proxy,
            "remote_login": remote_login
        }
        tornado.web.Application.__init__(self, handlers, **settings)
        logger.info("created Application")

class BaseHandler(tornado.web.RequestHandler):
    def initialize(self):
        self.log = self.application.settings.get('logger')
        self.saml_path = self.application.settings.get('saml_path')
        self.https_reverse_proxy = self.application.settings.get('https_reverse_proxy')
        self.remote_login = self.application.settings.get('remote_login')
        
        self.special_chars = "@!%*#?§+"
        self.pw_min = 8
        self.pw_max = 20
        self.reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[{}])[A-Za-z0-9{}]{}$".format(
                self.special_chars, self.special_chars,
                "{"+str(self.pw_min)+","+str(self.pw_max)+"}"
                )
        
    def get_current_user(self):
        return self.get_secure_cookie("uid", max_age_days=1)
    
class SAMLHandler(BaseHandler):
    def prepare(self):
        request = self.request
        dataDict = {}
        for key in request.arguments:
            dataDict[key] = request.arguments[key][0].decode('utf-8')

        https = request == 'https' or self.https_reverse_proxy
        self.saml_req = {
            'https': 'on' if https else 'off',
            'http_host': tornado.httputil.split_host_and_port(request.host)[0],
            'script_name': request.path,
            'server_port': tornado.httputil.split_host_and_port(request.host)[1],
            'get_data': dataDict,
            'post_data': dataDict,
            'query_string': request.query
        }
    
    def init_saml_auth(self):
        self.auth = OneLogin_Saml2_Auth(
                self.saml_req, custom_base_path=self.saml_path
                )
        return self.auth
    
class FormularHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        errors = None
        if "error" in self.request.arguments:
            errors = ["Please follow the password rules and type in the same password twice."]
        self.render(
                "formular.html", errors=errors,
                special_chars=self.special_chars,
                min_chars=self.pw_min, max_chars=self.pw_max
                )
    
class CreateHandler(BaseHandler):
    @tornado.web.authenticated
    def post(self):
        pw1 = self.request.arguments["pw1"]
        pw2 = self.request.arguments["pw2"]
        
        # compiling regex 
        pat = re.compile(self.reg)
        if pw1 != pw2 or not re.search(pat, pw1):
            self.redirect(self.reverse_url("formular")+"?error")
            
        uname = self.get_secure_cookie("uid", max_age_days=1)
        # create new user
        proc = Popen(
                ["adduser", uname], stdout=PIPE, stderr=PIPE,
                preexec_fn=preexec_fn
                )
        out, err = proc.communicate()
        if err != "":
            self.log.error("adduser %s: %s", uname, err)
            self.set_status(500)
            self.write("Internal Server Error - Errorcode 500")
        else:
            self.log.info("adduser %s was succesfull", uname)
            
            parent_conn, child_conn = Pipe()
            p = Process(target=set_pwd, args=(uname, pw1, child_conn,))
            p.start()
            retval = parent_conn.recv()
            p.join()
            if retval == 0:
                self.log.info("set pwd for %s was succesfull", uname)
                self.render("success.html", remote_login=self.remote_login)
            else:
                self.log.error("set pwd for %s PAMError %s", uname, retval)
                self.set_status(500)
                self.write("Internal Server Error - Errorcode 500")
            

class IndexHandler(BaseHandler):
    def get(self):self.render('index.html', remote_login=self.remote_login)

class ACSHandler(SAMLHandler):
    # disable xsrf here...
    def check_xsrf_cookie(self):
        pass
    
    def post(self):
        auth = self.init_saml_auth()
        error_reason = None
        auth.process_response()
        errors = auth.get_errors()

        if len(errors) == 0:
            attributes = auth.get_attributes()
            
            # test if user has the correct attributes
            if not "students" in attributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.1"]:
                self.log.info("user is not a student.")
                self.render("not_entitled.html")
            if not "Fb13" in attributes["urn:oid:1.3.6.1.4.1.8974.2.1.866"]:
                self.log.info("user is not a physicist.")
                self.render("not_entitled.html")
                
            uname = attributes["urn:oid:0.9.2342.19200300.100.1.1"]
            user_exists = True
            try:
                entry = pwd.getpwnam(uname)
            except KeyError:
                user_exists = False
            if user_exists:
                self.log.info("user %s exists already.", uname)
                self.render("user_exists.html", uname=uname)
            else:
                self.set_secure_cookie(
                        "uid", uname,
                        expires_days=1
                        )
                self.log.info("user %s authenticated.", uname)
                self.redirect(self.reverse_url("formular"))
            
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()

        self.render(
                'index.html', errors=errors, error_reason=error_reason,
                remote_login=self.remote_login
                )
        
class SSOHandler(SAMLHandler):
    def get(self):
        self.init_saml_auth()
        return self.redirect(self.auth.login(self.reverse_url("formular")))
    
class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_all_cookies()
        self.redirect(self.reverse_url("index"))

class MetadataHandler(SAMLHandler):
    def get(self):
        auth = self.init_saml_auth()
        saml_settings = auth.get_settings()
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)

        if len(errors) == 0:
            # resp = HttpResponse(content=metadata, content_type='text/xml')
            self.set_header('Content-Type', 'text/xml')
            self.write(metadata)
        else:
            self.log.error(', '.join(errors))
            self.set_status(500)
            self.write("Internal Server Error - Errorcode 500")

def preexec_fn():
    """Set the subprocess to root user"""
    os.setuid(0)
    os.getuid(0)
    
def set_pwd(username, password, conn):
    """Change to root"""
    os.setuid(0)
    os.getuid(0)
    retval = pamela.change_password(
            username, password, service="login", encoding='utf-8'
            )
    conn.send(retval)

def main():
    parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            description="""sso2linuxuser: create linux user after SSO"""
            )
    
    parser.add_argument(
            "--saml_path", help="base", type=str,
            default="/opt/jupyterhub/etc/sso2linuxuser"
            )
    parser.add_argument(
            "--base_url", help="base", type=str,
            default=r"/shibboleth"
            )
    parser.add_argument(
            "--remote_login", help="base", type=str,
            default=r"/jupyterhub"
            )
    parser.add_argument(
            "--port", help="base", type=int,
            default=8002
            )
    parser.add_argument(
            "--secret_nbytes", help="base", type=int,
            default=32
            )
    parser.add_argument(
            "--debug", help="base", action="store_true"
            )
    parser.add_argument(
            "--https_reverse_proxy", help="base", action="store_true"
            )
    parser.add_argument(
            "--syslog_address", type=str,
            default='/dev/log'
            )
    
    args = parser.parse_args()    
    port = args.port
    debug = args.debug
    
    loglevel = logging.DEBUG if debug else logging.INFO
    logger = logging.getLogger('sso2linuxuser')
    logger.setLevel(loglevel)
    h = SysLogHandler(address=args.syslog_address, facility="daemon")
    formatter = logging.Formatter(
            '[%(name)s-%(levelname)s %(lineno)d] %(message)s'
            )
    h.setFormatter(formatter)
    h.setLevel(loglevel)
    logger.addHandler(h)
    
    h2 = SysLogHandler(address=args.syslog_address, facility="daemon")
    formatter = logging.Formatter(
            '[%(name)s-%(levelname)s tornado] %(message)s'
            )
    h2.setFormatter(formatter)
    h2.setLevel(loglevel)
    logging.getLogger("tornado.access").addHandler(h2)
    logging.getLogger("tornado.application").addHandler(h2)
    logging.getLogger("tornado.general").addHandler(h2)
    
    # create cookie secret
    cookie_secret = secrets.token_hex(args.secret_nbytes)
    
    app = Application(
            cookie_secret=cookie_secret, saml_path=args.saml_path,
            logger=logger, debug=debug,
            base_url=args.base_url,
            https_reverse_proxy=args.https_reverse_proxy,
            remote_login=args.remote_login
            )
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(port)
    logger.info("Listening on port %i", port)
    tornado.ioloop.IOLoop.instance().start()
    
if __name__ == "__main__":
    main()