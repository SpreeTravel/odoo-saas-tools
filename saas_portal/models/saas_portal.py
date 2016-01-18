# -*- coding: utf-8 -*-
import requests
import simplejson
import openerp
from openerp.addons.web.http import request
from openerp import models, fields, api
from openerp.addons.saas_utils import connector, database
from openerp.tools import config
import datetime
import logging

_logger = logging.getLogger(__name__)

class OauthApplication(models.Model):
    _inherit = 'oauth.application'

    name = fields.Char('Database name', readonly=True)
    client_id = fields.Char('Client ID', readonly=True, select=True)
    users_len = fields.Integer('Count users', readonly=True)
    file_storage = fields.Integer('File storage (MB)', readonly=True)
    db_storage = fields.Integer('DB storage (MB)', readonly=True)
    server = fields.Char('Server', readonly=True)
    plan = fields.Char(compute='_get_plan', string='Plan', size=64)

    last_connection = fields.Char(compute='_get_last_connection',
                                  string='Last Connection', size=64)
    sub_status = fields.Char(compute='_get_subscription_status',
                             string='Subscription Status', size=64)

    def edit_db(self, cr, uid, ids, context=None):
        obj = self.browse(cr, uid, ids[0])
        return {
            'type': 'ir.actions.act_window',
            'view_type': 'form',
            'view_mode': 'form',
            'res_model': 'saas.config',
            'target': 'new',
            'context': {
                'default_action': 'edit',
                'default_database': obj.name
            }
        }

    def upgrade_db(self, cr, uid, ids, context=None):
        obj = self.browse(cr, uid, ids[0])
        return {
            'type': 'ir.actions.act_window',
            'view_type': 'form',
            'view_mode': 'form',
            'res_model': 'saas.config',
            'target': 'new',
            'context': {
                'default_action': 'upgrade',
                'default_database': obj.name
            }
        }

    def unlink(self, cr, uid, ids, context=None):
        user_model = self.pool.get('res.users')
        token_model = self.pool.get('oauth.access_token')
        for obj in self.browse(cr, uid, ids):
            to_search1 = [('application_id', '=', obj.id)]
            tk_ids = token_model.search(cr, uid, to_search1, context=context)
            if tk_ids:
                token_model.unlink(cr, uid, tk_ids)
            to_search2 = [('database', '=', obj.name)]
            user_ids = user_model.search(cr, uid, to_search2, context=context)
            if user_ids:
                user_model.unlink(cr, uid, user_ids)
            openerp.service.db.exp_drop(obj.name)
        return super(OauthApplication, self).unlink(cr, uid, ids, context)

    @api.one
    def _get_plan(self):
        oat = self.pool.get('oauth.access_token')
        to_search = [('application_id', '=', self.id)]
        access_token_ids = oat.search(self.env.cr, self.env.uid, to_search)
        if access_token_ids:
            access_token = oat.browse(self.env.cr, self.env.uid,
                                      access_token_ids[0])
            self.plan = access_token.user_id.plan_id.name

    @api.one
    def _get_last_connection(self):
        try:
            user_id = connector.call(self.name, 'res.users', 'search',
                                     [('active', '=', True),
                                      ('share', '=', False),
                                      ('id', '>', 1)],
                                     order='login_date desc'
                                    )[0]
            user = connector.call(self.name, 'res.users', 'read', user_id,
                                  ['login', 'login_date'])
            self.last_connection = user.get('login_date')
        except Exception, e:
            _logger.info("\n\n[%s] Exception caught: %s\n", self.name, e)
            self.last_connection = "No login recorded"

    @api.one
    def _get_subscription_status(self):
        oat = self.pool.get('oauth.access_token')
        to_search = [('application_id', '=', self.id)]
        access_token_ids = oat.search(self.env.cr, self.env.uid, to_search)
        if access_token_ids:
            access_token = oat.browse(self.env.cr, self.env.uid,
                                      access_token_ids[0])
            plan = access_token.user_id.plan_id
            if plan and hasattr(plan, 'pricing_ids') and plan.pricing_ids:
                trial_days = plan.pricing_ids[0].trial_period_days
                hoy = datetime.date.today()
                create_date = access_token.user_id.create_date
                create_date = create_date.split(' ')
                year, month, day = (int(x) for x in create_date[0].split('-'))
                ans = datetime.date(year, month, day)
                dif = hoy - ans
                if access_token.user_id.stripe_plan_id != False:
                    self.sub_status = access_token.user_id.stripe_plan_id
                else:
                    if dif.days <= int(trial_days):
                        x_days = int(trial_days) - dif.days
                        self.sub_status = "Trial - " + str(x_days)
                    else:
                        self.sub_status = "Need subscription"


class SaasConfig(models.TransientModel):
    _name = 'saas.config'

    action = fields.Selection([('edit', 'Edit'), ('upgrade', 'Upgrade')],
                                'Action')
    database = fields.Char('Database', size=128)
    update_addons = fields.Char('Update Addons', size=256)
    install_addons = fields.Char('Install Addons', size=256)
    uninstall_addons = fields.Char('Uninstall Addons', size=256)
    fix_ids = fields.One2many('saas.config.fix', 'config_id', 'Fixes')
    description = fields.Text('Result')

    def execute_action(self, cr, uid, ids, context=None):
        res = False
        obj = self.browse(cr, uid, ids[0], context)
        method = '%s_database' % obj.action
        if hasattr(self, method):
            res = getattr(self, method)(cr, uid, obj, context)
        return res

    def edit_database(self, cr, uid, obj, context=None):
        host = obj.database.replace('_', '.')
        if '.com' not in host:
            host = config.get('local_ip')
        params = (host, obj.database, config.get('tenant_passwd'))
        url = 'http://%s/login?db=%s&login=admin&key=%s' % params
        return {
            'type': 'ir.actions.act_url',
            'target': 'self',
            'name': 'Edit Database',
            'url': url
        }

    def upgrade_database(self, cr, uid, obj, context=None):
        res = {}
        scheme = request.httprequest.scheme
        # scheme = 'https'
        payload = simplejson.dumps({
            'update_addons': obj.update_addons or '',
            'install_addons': obj.install_addons or '',
            'uninstall_addons': obj.uninstall_addons or '',
            'fixes': ','.join(['%s-%s' % (x.model, x.method) for x in obj.fix_ids]),
            'csrf_token': request.csrf_token(),
        })

        dbs = obj.database and obj.database.split(',') or database.get_market_dbs(False)
        for db in dbs:
            url = '{scheme}://{domain}/saas_client/upgrade_database'.format(scheme=scheme, domain=db.replace('_', '.'))
            _logger.info("\n\n[POST] %s : %s\n", url, payload)
            r = requests.post(url, data=payload)
            res[db] = r.status_code
        self.write(cr, uid, obj.id, {'description': str(res)})
        return {
            'type': 'ir.actions.act_window',
            'view_type': 'form',
            'view_mode': 'form',
            'res_model': 'saas.config',
            'res_id': obj.id,
            'target': 'new'
        }


class SaasConfigFix(models.TransientModel):
    _name = 'saas.config.fix'

    model = fields.Char('Model', required=1, size=64)
    method = fields.Char('Method', required=1, size=64)
    config_id = fields.Many2one('saas.config', 'Config')
