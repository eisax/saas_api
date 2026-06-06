from odoo import api, fields, models, _

class PurchaseOrder(models.Model):
    _inherit = 'purchase.order'

    state = fields.Selection(
        selection_add=[('fully_billed', 'Fully BILLED')],
        ondelete={'fully_billed': 'set default'}
    )
