# -*- coding: utf-8 -*-
import functools
import logging

import simplejson
import urlparse
import urllib2
import werkzeug.utils
from werkzeug.exceptions import BadRequest

import openerp
from openerp import SUPERUSER_ID
from openerp import http
from openerp.http import request
from openerp.addons.web.controllers.main import Home, db_monodb, ensure_db, set_cookie_and_redirect, login_and_redirect
from openerp.addons.saas_portal.controllers.main import OAuthLogin as Home
from openerp.addons.auth_oauth.controllers.main import OAuthLogin, fragment_to_query_string
from openerp.modules.registry import RegistryManager
from openerp.tools.translate import _

_logger = logging.getLogger(__name__)


class SaasOAuthLogin (OAuthLogin):
    def list_providers(self):
        try:
            provider_obj = request.registry.get('auth.oauth.provider')
            providers = provider_obj.search_read(request.cr, SUPERUSER_ID, [('enabled', '=', True), ('auth_endpoint', '!=', False), ('validation_endpoint', '!=', False)])
            # TODO in forwardport: remove conditions on 'auth_endpoint' and 'validation_endpoint' when these fields will be 'required' in model
        except Exception:
            providers = []
        for provider in providers:
            provider_return_url = provider.get ('return_url', False)
            if not provider_return_url:
                provider_return_url = 'auth_oauth/signin'

            provider_response_type = provider.get ('response_type', False)
            if not provider_response_type:
                provider_response_type = 'token'
            
            return_url = request.httprequest.url_root + provider_return_url
            state = self.get_state(provider)
            params = dict(
                debug=request.debug,
                response_type=provider_response_type,
                client_id=provider['client_id'],
                redirect_uri=return_url,
                scope=provider['scope'],
                state=simplejson.dumps(state),
                # endpoint='http://localhost:3000/oauth/token'#provider['auth_endpoint'],
            )
            provider['auth_link'] = provider['auth_endpoint'] + '?' + werkzeug.url_encode(params)
            # provider['auth_link'] = '/auth_oauth/cenit_external_password' + '?' + werkzeug.url_encode(params)

        return providers


class ExternalOAuthController (http.Controller):
    
    @http.route ('/auth_oauth/cenit_signin', type='http', auth='none')
    @fragment_to_query_string
    def cenit_signin (self, **kw):
        state = simplejson.loads(kw['state'])
        dbname = state['d']
        provider = state['p']
        context = state.get('c', {})
        registry = RegistryManager.get(dbname)
        with registry.cursor() as cr:
            try:
                _logger.info ("Accessing users")
                u = registry.get('res.users')
                _logger.info ("Requesting credentials")
                credentials = u.cenit_auth_oauth_code (cr, SUPERUSER_ID, provider, kw, context=context)
                _logger.info ("Credentials: %s", credentials)
                cr.commit()
                action = state.get('a')
                menu = state.get('m')
                redirect = werkzeug.url_unquote_plus(state['r']) if state.get('r') else False
                url = '/web'
                if redirect:
                    url = redirect
                elif action:
                    url = '/web#action=%s' % action
                elif menu:
                    url = '/web#menu_id=%s' % menu
                return login_and_redirect(*credentials, redirect_url=url)
            except AttributeError:
                # auth_signup is not installed
                _logger.error("auth_signup not installed on database %s: oauth sign up cancelled." % (dbname,))
                url = "/web/login?oauth_error=1"
            except openerp.exceptions.AccessDenied:
                # oauth credentials not valid, user could be on a temporary session
                _logger.info('OAuth2: access denied, redirect to main page in case a valid session exists, without setting cookies')
                url = "/web/login?oauth_error=3"
                redirect = werkzeug.utils.redirect(url, 303)
                redirect.autocorrect_location_header = False
                return redirect
            except Exception, e:
                # signup error
                _logger.exception("OAuth2: %s" % str(e))
                url = "/web/login?oauth_error=2"

        return set_cookie_and_redirect(url)
    
    @http.route ('/auth_oauth/cenit', type='http', auth='none')
    def cenit_external_auth (self, **kw):
        """login user via CenitSaaS provider"""
        dbname = kw.pop('db', None)
        if not dbname:
            dbname = db_monodb()
        if not dbname:
            return BadRequest()

        registry = RegistryManager.get(dbname)
        with registry.cursor() as cr:
            IMD = registry['ir.model.data']
            try:
                model, provider_id = IMD.get_object_reference(cr, SUPERUSER_ID, 'external_oauth_provider', 'provider_cenit')
            except ValueError:
                return set_cookie_and_redirect('/web?db=%s' % dbname)
            assert model == 'auth.oauth.provider'

        state = {
            'd': dbname,
            'p': provider_id,
            'c': {'no_user_creation': True},
        }

        kw['state'] = simplejson.dumps (state)
        _logger.info ("\n\tKW: %s", kw)
        return self.cenit_signin(**kw)


class AuthSignupHome (Home):

    def __login (self, kw):
        state = simplejson.loads(kw['state'])
        dbname = state['d']
        provider = state['p']
        context = state.get('c', {})
        registry = RegistryManager.get(dbname)
        with registry.cursor() as cr:
            try:
                u = registry.get('res.users')
                credentials = u.cenit_auth_oauth_password (cr, SUPERUSER_ID, provider, kw, context=context)
                _logger.info ("Credentials: %s", credentials)
                cr.commit()
                action = state.get('a')
                menu = state.get('m')
                redirect = werkzeug.url_unquote_plus(state['r']) if state.get('r') else False
                url = '/web'
                if redirect:
                    url = redirect
                elif action:
                    url = '/web#action=%s' % action
                elif menu:
                    url = '/web#menu_id=%s' % menu
                return login_and_redirect(*credentials, redirect_url=url)
            except AttributeError:
                # auth_signup is not installed
                _logger.error("auth_signup not installed on database %s: oauth sign up cancelled." % (dbname,))
                url = "/web/login?oauth_error=1"
            except openerp.exceptions.AccessDenied:
                # oauth credentials not valid, user could be on a temporary session
                _logger.info('OAuth2: access denied, redirect to main page in case a valid session exists, without setting cookies')
                url = "/web/login?oauth_error=3"
                redirect = werkzeug.utils.redirect(url, 303)
                redirect.autocorrect_location_header = False
                return redirect
            except Exception, e:
                # signup error
                _logger.exception("OAuth2: %s" % str(e))
                url = "/web/login?oauth_error=2"

        return set_cookie_and_redirect(url)
    
    @http.route()
    def web_login(self, redirect=None, **kw):
        ensure_db()

        if kw.get('login', False):
            state = {}
            user = request.registry.get('res.users')
            domain = [('login', '=', kw['login'])]
            fields = ['oauth_provider_id',] # 'database']
            data = user.search_read(request.cr, SUPERUSER_ID, domain, fields)

            try:
                state.update ({
                    'd': kw['db'],
                    # 'd': data[0]['database'],
                    'p': data[0]['oauth_provider_id'][0],
                    'c': {'no_user_creation': True},
                })
            except Exception, e:
                _logger.info ("\n\tException ocurred: [%s]", e)
                return super(AuthSignupHome, self).web_login(redirect, **kw)

            kw.update ({'state': simplejson.dumps (state)})
            _logger.info ("\n\tKW: %s", kw)
            return self.__login (kw)
        else:    
            return super(AuthSignupHome, self).web_login(redirect, **kw)
