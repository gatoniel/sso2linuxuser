# -*- coding: utf-8 -*-
"""
Created on Thu Apr  9 17:20:43 2020

@author: niklas
"""

import os
import secrets
import argparse
import logging
from logging.handlers import SysLogHandler

import tornado.ioloop
import tornado.web
import tornado.httpserver
import tornado.httputil

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

session = {}

class Application(tornado.web.Application):
    def __init__(
            self, cookie_secret, saml_path, logger, debug=False, base_url="/"
            ):
        BASE_DIR = os.path.dirname(__file__)
        TEMPLATE_PATH = os.path.join(BASE_DIR, 'templates')
        logger.debug("TEMPLATE PATH: %s", TEMPLATE_PATH)
        
        config = {
                "logger": logger, "saml_path": saml_path,
                }
        
        handlers_tmp = [
            (r"/", IndexHandler, config),
            (r"/sso", SSOHandler, config, "login_sso"),
            (r"/attrs", AttrsHandler, config),
            (r"/acs", ACSHandler, config),
#            (r"/create", CreateHandler, config),
            (r"/metadata", MetadataHandler, config),
        ]
        handlers = [
                (base_url+x0, x1, x2) for (x0,x1,x2) in handlers_tmp
                ]        
        settings = {
            "template_path": TEMPLATE_PATH,
            "autorealod": True,
            "debug": debug,
#            "xsrf_cookies": True,
            "login_url": self.reverse_url("login_sso")
        }
        tornado.web.Application.__init__(self, handlers, **settings)
        logger.info("created Application")

class BaseHandler(tornado.web.RequestHandler):
    def initialize(self, logger, saml_path):
        self.log = logger
        self.saml_path = saml_path
        
    def prepare(self):
        self.saml_req = prepare_tornado_request(self.request)
        
    def get_current_user(self):
        pass
    
    def init_saml_auth(self):
        self.auth = OneLogin_Saml2_Auth(
                self.saml_req, custom_base_path=self.saml_path
                )
        return self.auth

class IndexHandler(BaseHandler):
    def post(self):
        auth = self.init_saml_auth()
        error_reason = None
        attributes = False
        paint_logout = False
        success_slo = False

        auth.process_response()
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()

        if len(errors) == 0:
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(self.saml_req)
            if 'RelayState' in self.request.arguments and self_url != self.request.arguments['RelayState'][0].decode('utf-8'):
                return self.redirect(self.request.arguments['RelayState'][0].decode('utf-8'))
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()

        if 'samlUserdata' in session:
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()

        self.render('index.html', errors=errors, error_reason=error_reason, not_auth_warn=not_auth_warn, success_slo=success_slo, attributes=attributes, paint_logout=paint_logout)

    def get(self):
        req = self.saml_req
        auth = self.init_saml_auth()
        error_reason = None
        errors = []
        not_auth_warn = False
        success_slo = False
        attributes = False
        paint_logout = False


        if 'slo' in req['get_data']:
            self.log.info('-slo-')
            name_id = None
            session_index = None
            if 'samlNameId' in session:
                name_id = session['samlNameId']
            if 'samlSessionIndex' in session:
                session_index = session['samlSessionIndex']
            return self.redirect(auth.logout(name_id=name_id, session_index=session_index))
        elif 'acs' in req['get_data']:
            self.log.info('-acs-')
            auth.process_response()
            errors = auth.get_errors()
            not_auth_warn = not auth.is_authenticated()
            if len(errors) == 0:
                session['samlUserdata'] = auth.get_attributes()
                session['samlNameId'] = auth.get_nameid()
                session['samlSessionIndex'] = auth.get_session_index()
                self_url = OneLogin_Saml2_Utils.get_self_url(req)
                if 'RelayState' in self.request.arguments and self_url != self.request.arguments['RelayState'][0].decode('utf-8'):
                    return self.redirect(auth.redirect_to(self.request.arguments['RelayState'][0].decode('utf-8')))
                elif auth.get_settings().is_debug_active():
                    error_reason = auth.get_last_error_reason()
        elif 'sls' in req['get_data']:
            self.log.info('-sls-')
            dscb = lambda: session.clear()  # clear out the session
            url = auth.process_slo(delete_session_cb=dscb)
            errors = auth.get_errors()
            if len(errors) == 0:
                if url is not None:
                    return self.redirect(url)
                else:
                    success_slo = True
            elif auth.get_settings().is_debug_active():
                error_reason = auth.get_last_error_reason()
        if 'samlUserdata' in session:
            self.log.info('-samlUserdata-')
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()
                self.log.info("ATTRIBUTES", attributes)
        self.render('index.html', errors=errors, error_reason=error_reason, not_auth_warn=not_auth_warn, success_slo=success_slo, attributes=attributes, paint_logout=paint_logout)

class ACSHandler(BaseHandler):
    def post(self):
        auth = self.init_saml_auth()
        error_reason = None
        attributes = False
        paint_logout = False
        success_slo = False

        auth.process_response()
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()

        if len(errors) == 0:
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(self.saml_req)
            if 'RelayState' in self.request.arguments and self_url != self.request.arguments['RelayState'][0].decode('utf-8'):
                return self.redirect(self.request.arguments['RelayState'][0].decode('utf-8'))
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()

        if 'samlUserdata' in session:
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()

        self.render('index.html', errors=errors, error_reason=error_reason, not_auth_warn=not_auth_warn, success_slo=success_slo, attributes=attributes, paint_logout=paint_logout)

class SSOHandler(BaseHandler):
    def get(self):
        self.init_saml_auth()
        self.log.info('-sso-')
        return self.redirect(self.auth.login())

class AttrsHandler(BaseHandler):
    def get(self):
        paint_logout = False
        attributes = False

        if 'samlUserdata' in session:
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()

        self.render('attrs.html', paint_logout=paint_logout, attributes=attributes)


class MetadataHandler(BaseHandler):
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
            # resp = HttpResponseServerError(content=', '.join(errors))
            self.write(', '.join(errors))
        # return resp


def prepare_tornado_request(request):
    dataDict = {}
    for key in request.arguments:
        dataDict[key] = request.arguments[key][0].decode('utf-8')

    result = {
        'https': 'on' if request == 'https' else 'off',
        'http_host': tornado.httputil.split_host_and_port(request.host)[0],
        'script_name': request.path,
        'server_port': tornado.httputil.split_host_and_port(request.host)[1],
        'get_data': dataDict,
        'post_data': dataDict,
        'query_string': request.query
    }
    return result

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
            default=r"/"
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
    
    # create cookie secret
    cookie_secret = secrets.token_hex(args.secret_nbytes)
    
    app = Application(
            cookie_secret=cookie_secret, saml_path=args.saml_path,
            logger=logger, debug=debug,
            base_url=args.base_url
            )
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(port)
    logger.info("Listening on port %i", port)
    tornado.ioloop.IOLoop.instance().start()
    
if __name__ == "__main__":
    main()