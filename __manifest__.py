# -*- coding: utf-8 -*-
{
    'name': 'SaaS API',
    'version': '1.0',
    'category': 'Sales',
    'summary': 'REST API endpoints for SaaS integration (login, get products, make sale, add item)',
    'description': """
        Exposes REST JSON API endpoints for SaaS integrations:
        - POST /saas_api/login
        - POST /saas_api/products (and get_products)
        - POST /saas_api/make_sale
        - POST /saas_api/add_item
    """,
    'depends': ['sale_management', 'stock', 'purchase', 'account'],
    'data': [
        'views/purchase_order_views.xml',
    ],
    'installable': True,
    'application': True,
    'auto_install': False,
    'license': 'LGPL-3',
}
