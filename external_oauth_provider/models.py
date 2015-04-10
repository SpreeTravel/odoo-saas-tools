# -*- coding: utf-8 -*-
import logging

import werkzeug.urls
import urlparse
import urllib2
import simplejson
import openerp

from openerp.http import request
from openerp.addons.auth_signup.res_users import SignupError
from openerp import models, fields, api, SUPERUSER_ID

_logger = logging.getLogger(__name__)

class auth_oauth_provider (models.Model):
    _inherit = 'auth.oauth.provider'

    return_url = fields.Char('Return URL')
    response_type = fields.Char('Response Type')
    

class res_users(models.Model):
    _inherit = "res.users"

    def _cenit_auth_oauth_rpc_post (self, cr, uid, endpoint, data):
        """ performs a POST request to a given endpoint with a given data """
        
        params = werkzeug.url_encode (data)
        req = urllib2.Request (endpoint, params)
        _logger.info ("POSTing to %s", req.get_full_url ())
        try:
            f = urllib2.urlopen (req)
        except Exception, e:
            _logger.info ("\n\tError [%s]", e.read())
            raise e
        response = f.read()
        _logger.info ("\n\tResponse: %s", response)

        return simplejson.loads(response)

    def _cenit_auth_oauth_rpc_get (self, cr, uid, endpoint, access_token):
        """ performs a GET request to a given endpoint with a given access_token """
        
        params = werkzeug.url_encode({'access_token': access_token})
        if urlparse.urlparse(endpoint)[4]:
            req = endpoint + '&' + params
        else:
            req = endpoint + '?' + params
        
        _logger.info ("GETing to %s", req)
        try:
            f = urllib2.urlopen (req)
        except Exception, e:
            _logger.info ("\n\tError [%s]", e.read())
            raise e
        response = f.read()

        _logger.info ("\n\tResponse: %s", response)

        return simplejson.loads(response)

    def __get_oauth_provider (self, cr, uid, provider, context=None):
        """ retrieves data on a given provider """
        
        return self.pool.get ('auth.oauth.provider').browse (cr,
            uid,
            provider,
            context=context
        )
    
    def __cenit_auth_oauth_validation (self, cr, uid, endpoint, data):
        """ requests validation from provider's validation endpoint """
        
        validation = self._cenit_auth_oauth_rpc_post (cr, uid, endpoint, data)
        if validation.get("error"):
            raise Exception(validation['error'])
        
        return validation
        
    def __cenit_auth_oauth_data (self, cr, uid, endpoint, data):
        """ requests data from provider's validation endpoint """
        
        validation = self._cenit_auth_oauth_rpc_get (cr, uid, endpoint, data)
        if validation.get("error"):
            raise Exception(validation['error'])
        
        return validation
        
    def _cenit_auth_oauth_code_validate (self, cr, uid, provider, code, context=None):
        """ return the validation data corresponding to the access token """
        
        _logger.info ("Requesting provider")
        p = self.__get_oauth_provider (cr, uid, provider, context=context)
        params = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': p.client_id,
            'client_secret': '2f2c6591cf97745f32f6060d464016474ffa51a6b6e786956139109d86c91552',
            'redirect_uri': request.httprequest.url_root + p.return_url,
        }

        _logger.info ("Requesting access token")
        validation = self.__cenit_auth_oauth_validation (cr, uid, p.validation_endpoint, params)
        access_token = validation.get('access_token', False)

        if p.data_endpoint and access_token:
            data = self._cenit_auth_oauth_rpc_get (cr, uid, p.data_endpoint, access_token)
            if data and data['resource_owner_id']['$oid']:
                validation.update({'user_id': data['resource_owner_id']['$oid']})
        
        return validation

    def _cenit_auth_oauth_password_validate(self, cr, uid, provider, data, context=None):
        """ return the validation data corresponding to a user:password pair """
        
        p = self.__get_oauth_provider(cr, uid, provider, context=context)
        params = {
            'grant_type': 'password',
            'client_id': p.client_id,
            'scope': p.scope,
            'username': data['login'],
            'password': data['password'],
        }

        validation = self.__cenit_auth_oauth_validation (cr, uid, p.validation_endpoint, params)
        access_token = validation.get('access_token', False)
        
        if p.data_endpoint and access_token:
            data = self._cenit_auth_oauth_rpc_get (cr, uid, p.data_endpoint, access_token)
            if data and data['resource_owner_id']['$oid']:
                validation.update({'user_id': data['resource_owner_id']['$oid']})
        
        
        return validation

    def _cenit_auth_oauth_signin(self, cr, uid, provider, validation, params, context=None):
        """ retrieve and sign in the user corresponding to provider and validated access token
            :param provider: oauth provider id (int)
            :param validation: result of validation of access token (dict)
            :param params: oauth parameters (dict)
            :return: user login (str)
            :raise: openerp.exceptions.AccessDenied if signin failed

            This method can be overridden to add alternative signin methods.
        """
        try:
            oauth_uid = validation['user_id']
            user_ids = self.search(cr, uid, [("oauth_uid", "=", oauth_uid), ('oauth_provider_id', '=', provider)])
            if not user_ids:
                raise openerp.exceptions.AccessDenied()
            assert len(user_ids) == 1
            user = self.browse(cr, uid, user_ids[0], context=context)
            user.write({'oauth_access_token': params['access_token']})
            return user.login
        except openerp.exceptions.AccessDenied, access_denied_exception:
            if context and context.get('no_user_creation'):
                return None
            state = simplejson.loads(params['state'])
            token = state.get('t')
            oauth_uid = validation['user_id']
            email = validation.get('email', 'provider_%s_user_%s' % (provider, oauth_uid))
            name = validation.get('name', email)
            values = {
                'name': name,
                'login': email,
                'email': email,
                'oauth_provider_id': provider,
                'oauth_uid': oauth_uid,
                'oauth_access_token': params['access_token'],
                'active': True,
            }
            try:
                _, login, _ = self.signup(cr, uid, values, token, context=context)
                return login
            except SignupError:
                raise access_denied_exception

    def __cenit_get_credentials (self, cr, uid, provider, validation, params, context=None):
        """ passes validation result to get login credentials """
        
        _logger.info ("\n\tValidation: %s", validation)
        # required check
        if not validation.get('user_id'):
            raise openerp.exceptions.AccessDenied()
        
        # retrieve and sign in user
        login = self._cenit_auth_oauth_signin(cr, uid, provider, validation, params, context=context)
        if not login:
            raise openerp.exceptions.AccessDenied()

        # return user credentials
        return (cr.dbname, login)
    
    def cenit_auth_oauth_password (self, cr, uid, provider, params, context=None):
        validation = self._cenit_auth_oauth_password_validate(cr, uid, provider, params)

        access_token = validation.get('access_token')
        params.update ({'access_token': access_token})
        
        (dbname, login) = self.__cenit_get_credentials (cr, uid, provider, validation, params, context=context)

        _logger.info ("\n\tCredentials: %s@%s", login, dbname)
        return (dbname, login, access_token)

    def cenit_auth_oauth_code(self, cr, uid, provider, params, context=None):
        code = params.get('code')
        _logger.info ("Attempting to validate code")
        validation = self._cenit_auth_oauth_code_validate(cr, uid, provider, code)

        access_token = validation.get('access_token')
        params.update ({'access_token': access_token})

        (dbname, login) = self.__cenit_get_credentials (cr, uid, provider, validation, params, context=context)
        return (dbname, login, access_token)
