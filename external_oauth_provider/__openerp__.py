# -*- coding: utf-8 -*-
{
    'name': "external_oauth_provider",

    'summary': "Support for external non-Odoo OAuth providers",

    'description': """
        This module intends to provide support for using third party
        OpenAuth providers other than www.odoo.com.

        So far only support for www.cenitsaas.com has been added.
    """,

    'author': "Cenit",
    'website': "http://www.cenitsaas.com",

    # Categories can be used to filter modules in modules listing
    # Check https://github.com/odoo/odoo/blob/master/openerp/addons/base/module/module_data.xml
    # for the full list
    'category': 'SaaS',
    'version': '0.1',

    # any module necessary for this one to work correctly
    'depends': ['web', 'auth_oauth'],

    # always loaded
    'data': [
        # 'security/ir.model.access.csv',
        'data.xml',
        'templates.xml',
    ],
    # only loaded in demonstration mode
    'demo': [
        'demo.xml',
    ],
}
