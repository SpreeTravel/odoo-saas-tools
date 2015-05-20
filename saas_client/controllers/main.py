# -*- coding: utf-8 -*-
import werkzeug
from openerp import http, SUPERUSER_ID
from openerp.http import request
from openerp.tools import config


class SaasClient(http.Controller):

    @http.route('/saas_client/new_database', type='http', auth='none')
    def new_database(self, **post):
        params = werkzeug.url_encode(post)
        return werkzeug.utils.redirect('/auth_oauth/signin?%s' % params)

    @http.route('/saas_client/upgrade_database', type='http', auth='none')
    def upgrade_database(self, **post):
        try:
            db = request.httprequest.host.replace('.', '_')
            pwd = config.get('tenant_passwd')
            uid = request.session.authenticate(db, SUPERUSER_ID, pwd)
            if uid:
                module = request.registry['ir.module.module']
                # 1. Update addons
                update_addons = post.get('update_addons', '').split(',')
                if update_addons:
                    upids = module.search(request.cr, SUPERUSER_ID,
                                          [('name', 'in', update_addons)])
                    if upids:
                        module.button_upgrade(request.cr, SUPERUSER_ID, upids)
                # 2. Install addons
                install_addons = post.get('install_addons', '').split(',')
                if install_addons:
                    inids = module.search(request.cr, SUPERUSER_ID,
                                          [('name', 'in', install_addons)])
                    if inids:
                        module.button_install(request.cr, SUPERUSER_ID, inids)
                # 3. Uninstall addons
                uninstall_addons = post.get('uninstall_addons', '').split(',')
                if uninstall_addons:
                    unids = module.search(request.cr, SUPERUSER_ID,
                                          [('name', 'in', uninstall_addons)])
                    if unids:
                        module.button_uninstall(request.cr, SUPERUSER_ID, unids)
                # 4. Run fixes
                fixes = post.get('fixes', '').split(',')
                for fix in fixes:
                    if fix:
                        model, method = fix.split('-')
                        getattr(request.registry[model], method)(request.cr,
                                                                 SUPERUSER_ID)
                status_code = 200
            else:
                status_code = 400
        except:
            status_code = 500
        return werkzeug.wrappers.Response(status=status_code)
