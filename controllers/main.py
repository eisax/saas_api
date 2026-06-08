# -*- coding: utf-8 -*-
import json
import base64
import logging
import odoo
from odoo import http, fields, api
from odoo.http import request
from odoo.modules.registry import Registry

_logger = logging.getLogger(__name__)


class SaasApiController(http.Controller):

    # =========================================================================
    # Helpers
    # =========================================================================
    def _get_env(self, user_id=None):
        params = self._get_request_json()
        db = request.httprequest.args.get('db') or params.get('db') or request.session.db
        
        if not db:
            db = request.db or request.env.cr.dbname
            if not db:
                try:
                    db_list = http.db_list()
                    if db_list:
                        db = db_list[0]
                except Exception:
                    pass
            
        uid = odoo.SUPERUSER_ID
        if user_id:
            try:
                uid = int(user_id)
            except ValueError:
                pass
                
        if db and db != request.env.cr.dbname:
            _logger.info(f"SaaS API: Switching database context from '{request.env.cr.dbname}' to '{db}' (user={uid})")
            registry = Registry(db)
            cr = registry.cursor()
            env = api.Environment(cr, uid, request.env.context or {})
            return env(su=True), cr
            
        if user_id and uid != request.env.uid:
            return request.env(user=uid, su=True), None
            
        return request.env(su=True), None

    def _make_json_response(self, data, status=200):
        body = json.dumps(data)
        headers = [
            ('Content-Type', 'application/json'),
            ('Content-Length', str(len(body))),
            ('Access-Control-Allow-Origin', '*'),
            ('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS'),
            ('Access-Control-Allow-Headers', 'Content-Type, Authorization'),
        ]
        return request.make_response(body, headers=headers, status=status)

    def _generate_token(self, user_id, login):
        token_str = f"{user_id}:{login}:saas_secret_key"
        token_bytes = token_str.encode('utf-8')
        return base64.b64encode(token_bytes).decode('utf-8')

    def _verify_token(self, token):
        if not token:
            return None, None
        if token.startswith("Bearer "):
            token = token[7:]
        elif token.startswith("token "):
            token = token[6:]

        # First try: parse as the tokenString format "uid:hash"
        # This is sent by the Flutter app's product_create.dart as 'token <uid>:<hash>'
        try:
            parts = token.split(':')
            if len(parts) == 2:
                uid = parts[0]
                # Validate that uid is a valid integer
                int(uid)
                return uid, None
        except (ValueError, Exception):
            pass

        # Second try: parse as base64-encoded "uid:login:saas_secret_key"
        try:
            token_bytes = base64.b64decode(token.encode('utf-8'))
            token_str = token_bytes.decode('utf-8')
            parts = token_str.split(':')
            if len(parts) == 3 and parts[2] == "saas_secret_key":
                return parts[0], parts[1]
        except Exception as e:
            _logger.error(f"Error decoding token: {e}")
        return None, None

    def _get_request_json(self):
        try:
            return json.loads(request.httprequest.data.decode('utf-8'))
        except Exception:
            return {}

    # =========================================================================
    # Routes
    # =========================================================================
    @http.route('/saas_api/login', type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def login(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        params = self._get_request_json()
        usr = params.get('usr')
        pwd = params.get('pwd')
        timezone = params.get('timezone', '')

        # Resolve database
        db = params.get('db') or request.httprequest.args.get('db') or request.session.db
        if not db:
            db = request.db or request.env.cr.dbname
            if not db:
                try:
                    db_list = http.db_list()
                    if db_list:
                        db = db_list[0]
                except Exception:
                    pass

        env, custom_cr = self._get_env()
        try:
            user_record = None
            federated_auth_success = False
            
            # 1. Try to authenticate against the SaaS Master first (Federated Auth)
            try:
                import requests
                SAAS_MASTER_URL = 'https://saas.havano.pro'
                login_url = f"{SAAS_MASTER_URL.rstrip('/')}/api/v1/auth/login"
                response = requests.post(
                    login_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "call",
                        "params": {
                            "email": usr,
                            "password": pwd,
                            "db": "saas"
                        }
                    },
                    timeout=5
                )
                response.raise_for_status()
                result = response.json().get('result', {})
                if result.get('success', True) and result.get('data'):
                    user_data = result.get('data')
                    email = user_data.get('email') or usr
                    name = user_data.get('name') or email
                    
                    # Find or create user locally
                    user_record = env['res.users'].search([('login', '=', email)], limit=1)
                    if not user_record:
                        _logger.info("Auto-provisioning federated user %s", email)
                        user_record = env['res.users'].with_context(no_reset_password=True).create({
                            'name': name,
                            'login': email,
                            'email': email,
                            'groups_id': [(6, 0, [env.ref('base.group_user').id, env.ref('base.group_erp_manager').id])]
                        })
                        import uuid
                        user_record.password = uuid.uuid4().hex
                        
                    federated_auth_success = True
                    _logger.info("Federated Login success for %s via SaaS Master", usr)
            except Exception as e:
                _logger.warning(f"Federated auth failed/skipped for {usr}: {e}")

            # 2. Fallback to local Odoo login if federated login was not successful
            if not federated_auth_success:
                try:
                    wsgienv = {
                        'interactive': True,
                        'base_location': request.httprequest.url_root.rstrip('/'),
                        'HTTP_HOST': request.httprequest.environ['HTTP_HOST'],
                        'REMOTE_ADDR': request.httprequest.environ['REMOTE_ADDR'],
                    }
                    credential = {'login': usr, 'password': pwd, 'type': 'password'}
                    auth_info = env['res.users'].authenticate(credential, wsgienv)
                    uid = auth_info.get('uid')
                    if uid:
                        user_record = env['res.users'].browse(uid)
                except Exception as e:
                    _logger.warning(f"Local Odoo auth failed for {usr} on database {db}: {e}")

            if not user_record:
                return self._make_json_response({"error": "Invalid credentials"}, status=401)

            full_name = user_record.name
            parts = full_name.split(' ', 1)
            first_name = parts[0]
            last_name = parts[1] if len(parts) > 1 else ""
            email = user_record.email or ""
            username = user_record.login
            token = self._generate_token(user_record.id, user_record.login)
            token_string = f"{user_record.id}:{hash(user_record.login)}"
            
            wh = env['stock.warehouse'].search([('company_id', '=', user_record.company_id.id)], limit=1)
            warehouse_name = wh.name if wh else ""
            company_name = user_record.company_id.name
            company_email = user_record.company_id.email or ""
            company_website = user_record.company_id.website or ""

            analytic_account = env['account.analytic.account'].search([], limit=1)
            cost_center_name = analytic_account.name if analytic_account else ""

            warehouse_items = []
            products = env['product.product'].search([('sale_ok', '=', True)], limit=100)
            for p in products:
                quants = env['stock.quant'].search([('product_id', '=', p.id)])
                warehouse_qtys = {}
                for q in quants:
                    product_wh = q.location_id.warehouse_id
                    if product_wh:
                        warehouse_qtys[product_wh.name] = warehouse_qtys.get(product_wh.name, 0.0) + q.quantity
                
                actual_qty = sum(warehouse_qtys.values()) if warehouse_qtys else 0.0
                
                warehouse_items.append({
                    "item_code": p.default_code or str(p.id),
                    "item_name": p.name,
                    "description": p.description_sale or p.name,
                    "stock_uom": p.uom_id.name or "",
                    "actual_qty": actual_qty,
                    "projected_qty": p.virtual_available or actual_qty
                })

            customers_list = []
            partners = env['res.partner'].search([('customer_rank', '>', 0)], limit=100)
            if not partners:
                partners = env['res.partner'].search([('is_company', '=', False)], limit=100)
            for pt in partners:
                customers_list.append({
                    "name": pt.name,
                    "customer_name": pt.name,
                    "customer_group": "Individual" if not pt.is_company else "Commercial",
                    "territory": pt.country_id.name if pt.country_id else "All Territories",
                    "custom_cost_center": cost_center_name
                })

            seen = set()
            dedup_customers = []
            for c in customers_list:
                if c["name"] not in seen:
                    seen.add(c["name"])
                    dedup_customers.append(c)

            default_customer = dedup_customers[0]["name"] if dedup_customers else ""

            response_data = {
                "message": "Logged In",
                "home_page": "/app",
                "full_name": full_name,
                "user": {
                    "first_name": first_name,
                    "last_name": last_name,
                    "gender": "",
                    "birth_date": "",
                    "mobile_no": "",
                    "username": username,
                    "full_name": full_name,
                    "email": email,
                    "warehouse": warehouse_name,
                    "cost_center": cost_center_name,
                    "default_customer": default_customer,
                    "customers": dedup_customers,
                    "warehouse_items": warehouse_items,
                    "time_zone": timezone,
                    "company": {
                        "name": company_name,
                        "email": company_email,
                        "website": company_website
                    }
                },
                "token_string": token_string,
                "token": token
            }

            return self._make_json_response(response_data)
        finally:
            if custom_cr:
                custom_cr.close()

    @http.route(['/saas_api/products', '/saas_api/get_products'], type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def get_products(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            products_list = []
            all_warehouses = env['stock.warehouse'].search([])
            warehouse_fallback = [{"warehouse": wh.name, "qtyOnHand": 0.0} for wh in all_warehouses]
            if not warehouse_fallback:
                warehouse_fallback = [{"warehouse": "", "qtyOnHand": 0.0}]

            odoo_products = env['product.product'].search([('sale_ok', '=', True)])
            for product in odoo_products:
                maintainstock = 1 if product.type == 'consu' else 0
                
                quants = env['stock.quant'].search([('product_id', '=', product.id)])
                warehouse_qtys = {}
                for q in quants:
                    product_wh = q.location_id.warehouse_id.name if q.location_id.warehouse_id else q.location_id.complete_name
                    if product_wh:
                        warehouse_qtys[product_wh] = warehouse_qtys.get(product_wh, 0.0) + q.quantity
                
                warehouses_data = []
                for wh_name, qty in warehouse_qtys.items():
                    warehouses_data.append({
                        "warehouse": wh_name,
                        "qtyOnHand": qty
                    })
                
                if not warehouses_data:
                    warehouses_data = list(warehouse_fallback)

                default_wh = warehouses_data[0]["warehouse"] if warehouses_data else ""

                prices = [
                    {"priceName": "Standard Buying", "price": product.standard_price or 0.0, "uom": product.uom_id.name or "", "type": "buying"},
                    {"priceName": "Standard Selling", "price": product.list_price or 0.0, "uom": product.uom_id.name or "", "type": "selling"}
                ]
                
                # Fetch price list rules from the product's prices tab (pricelist_rule_ids)
                for pl_item in product.pricelist_rule_ids:
                    price_val = 0.0
                    if pl_item.compute_price == 'fixed':
                        price_val = pl_item.fixed_price or 0.0
                    elif pl_item.compute_price == 'percentage':
                        price_val = product.list_price * (1 - (pl_item.percent_price or 0.0) / 100.0)
                    elif pl_item.compute_price == 'formula':
                        base_price = product.list_price
                        if pl_item.base == 'standard_price':
                            base_price = product.standard_price
                        price_val = base_price * (1 - (pl_item.price_discount or 0.0) / 100.0) + (pl_item.price_surcharge or 0.0)
                    
                    price_name = pl_item.pricelist_id.name or "Pricelist"
                    if pl_item.min_quantity > 0:
                        price_name = f"{price_name} (Min Qty {int(pl_item.min_quantity)})"
                        
                    prices.append({
                        "priceName": price_name,
                        "price": price_val or 0.0,
                        "uom": pl_item.product_uom_name or product.uom_id.name or "",
                        "type": "selling"
                    })
                
                taxes_data = []
                for tax in product.taxes_id:
                    name_lower = (tax.name or "").lower()
                    if 'vat' in name_lower:
                        tax_category = 'VAT'
                    elif 'food' in name_lower:
                        tax_category = 'Food Tax'
                    elif 'tourism' in name_lower:
                        tax_category = 'Tourism Tax'
                    else:
                        tax_category = tax.name or ""
                    
                    taxes_data.append({
                        "item_tax_template": tax.name or "",
                        "tax_category": tax_category,
                        "valid_from": None,
                        "minimum_net_rate": tax.amount or 0.0,
                        "maximum_net_rate": tax.amount or 0.0
                    })

                products_list.append({
                    "itemcode": product.default_code or str(product.id),
                    "itemname": product.name,
                    "groupname": product.categ_id.name or "",
                    "maintainstock": maintainstock,
                    "warehouses": warehouses_data,
                    "default warehouse": default_wh,
                    "prices": prices,
                    "taxes": taxes_data,
                    "simple_code": product.default_code or "",
                    "is_sales_item": 1,
                    "uom": {
                        "stock_uom": product.uom_id.name or "",
                        "conversions": [{"uom": product.uom_id.name or "", "conversion_factor": 1.0}]
                    },
                    "food_and_tourism_tax": 0, "food_tax": 0, "tourism_tax": 0, "cumulative": 0
                })
        except Exception as e:
            _logger.error(f"Error listing Odoo products: {e}")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

        return self._make_json_response({
            "message": {
                "products": products_list
            },
            "token_string": params.get('token_string', ""),
            "token": token
        })

    @http.route('/saas_api/make_sale', type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def make_sale(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        customer_name = params.get('customer') or ""
        lines = params.get('lines', [])

        if not lines:
            return self._make_json_response({"error": "No items in sale"}, status=400)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            partner = None
            if customer_name:
                partner = env['res.partner'].search([('name', '=', customer_name)], limit=1)
                if not partner:
                    partner = env['res.partner'].create({
                        'name': customer_name,
                        'customer_rank': 1
                    })
            if not partner:
                partner = env['res.partner'].search([], limit=1)

            sale_order = env['sale.order'].create({
                'partner_id': partner.id,
                'date_order': fields.Datetime.now(),
            })

            for line in lines:
                item_code = line.get('item_code')
                qty = float(line.get('qty', 1.0))
                price = float(line.get('price', 0.0))

                product = env['product.product'].search([
                    '|', ('default_code', '=', item_code), ('barcode', '=', item_code)
                ], limit=1)
                
                if not product and item_code.isdigit():
                    product = env['product.product'].browse(int(item_code))
                    if not product.exists():
                        product = None

                if not product:
                    raise Exception(f"Product not found in Odoo database with code: {item_code}")

                env['sale.order.line'].create({
                    'order_id': sale_order.id,
                    'product_id': product.id,
                    'product_uom_qty': qty,
                    'price_unit': price,
                })

            sale_order.action_confirm()

            if custom_cr:
                custom_cr.commit()

            return self._make_json_response({
                "message": "Sale created successfully",
                "sale_order_id": sale_order.id,
                "sale_order_name": sale_order.name
            })

        except Exception as e:
            _logger.exception("SaaS API: Error creating sale")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    @http.route('/saas_api/add_item', type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def add_item(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        item_code = params.get('item_code') or params.get('reference')
        item_name = params.get('item_name')
        description = params.get('description', item_name)
        stock_uom = params.get('stock_uom') or params.get('uom')
        
        price = params.get('price') or params.get('sales_price') or params.get('list_price')
        price = float(price) if price is not None else 0.0
        
        buying_price = params.get('buying_price') or params.get('cost') or params.get('standard_price')
        buying_price = float(buying_price) if buying_price is not None else (price * 0.6)
        
        qty_on_hand = float(params.get('qty_on_hand', 0.0))
        barcode = params.get('barcode', '')

        # Product type mapping: Goods -> consu, Service -> service, Combo -> combo
        prod_type_raw = params.get('product_type') or params.get('type') or 'Goods'
        prod_type = 'consu'
        if isinstance(prod_type_raw, str):
            prod_type_lower = prod_type_raw.lower()
            if 'service' in prod_type_lower:
                prod_type = 'service'
            elif 'combo' in prod_type_lower:
                prod_type = 'combo'
            elif 'goods' in prod_type_lower:
                prod_type = 'consu'
            elif prod_type_raw in ['consu', 'service', 'combo']:
                prod_type = prod_type_raw

        # Invoicing Policy: Ordered quantities -> order, Delivered quantities -> delivery
        inv_policy_raw = params.get('invoicing_policy') or params.get('invoice_policy')
        inv_policy = 'order'
        if isinstance(inv_policy_raw, str):
            inv_policy_lower = inv_policy_raw.lower()
            if 'delivery' in inv_policy_lower or 'delivered' in inv_policy_lower:
                inv_policy = 'delivery'
            elif 'order' in inv_policy_lower:
                inv_policy = 'order'

        # Track Inventory?
        track_inv_raw = params.get('track_inventory')
        track_inv = True
        if track_inv_raw is not None:
            if isinstance(track_inv_raw, str):
                track_inv = track_inv_raw.lower() in ['yes', 'true', '1']
            else:
                track_inv = bool(track_inv_raw)

        if not item_code or not item_name:
            return self._make_json_response({"error": "Missing required fields item_code or item_name"}, status=400)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            uom = None
            if stock_uom:
                uom = env['uom.uom'].search([('name', '=', stock_uom)], limit=1)
            if not uom:
                uom = env.ref('uom.product_uom_unit', raise_if_not_found=False) or env['uom.uom'].search([], limit=1)

            vals = {
                'name': item_name,
                'default_code': item_code,
                'description_sale': description,
                'list_price': price,
                'standard_price': buying_price,
                'type': prod_type,
                'invoice_policy': inv_policy,
            }
            if prod_type == 'consu':
                vals['is_storable'] = track_inv
            if uom:
                vals['uom_id'] = uom.id
            if barcode:
                vals['barcode'] = barcode

            # Resolving category
            category_input = params.get('category') or params.get('categ_id')
            if category_input:
                categ_record = None
                if isinstance(category_input, int):
                    categ_record = env['product.category'].browse(category_input)
                    if not categ_record.exists():
                        categ_record = None
                elif isinstance(category_input, str):
                    categ_record = env['product.category'].search([('name', '=', category_input)], limit=1)
                    if not categ_record:
                        categ_record = env['product.category'].search([('complete_name', '=', category_input)], limit=1)
                    if not categ_record:
                        categ_record = env['product.category'].search([('name', 'ilike', category_input)], limit=1)
                
                if categ_record:
                    vals['categ_id'] = categ_record.id

            # Resolving sales taxes
            tax_ids = []
            sales_taxes_input = params.get('sales_taxes') or params.get('taxes') or params.get('sales_tax')
            if sales_taxes_input:
                if not isinstance(sales_taxes_input, list):
                    sales_taxes_input = [sales_taxes_input]
                for tax_val in sales_taxes_input:
                    tax_record = None
                    if isinstance(tax_val, (int, float)):
                        tax_record = env['account.tax'].search([('amount', '=', float(tax_val)), ('type_tax_use', '=', 'sale')], limit=1)
                    elif isinstance(tax_val, str):
                        try:
                            val_float = float(tax_val.replace('%', '').strip())
                            tax_record = env['account.tax'].search([('amount', '=', val_float), ('type_tax_use', '=', 'sale')], limit=1)
                        except ValueError:
                            pass
                        if not tax_record:
                            tax_record = env['account.tax'].search([('name', 'ilike', tax_val), ('type_tax_use', '=', 'sale')], limit=1)
                    if tax_record:
                        tax_ids.append(tax_record.id)
            if tax_ids:
                vals['taxes_id'] = [(6, 0, tax_ids)]

            # Resolving purchase taxes
            purchase_tax_ids = []
            purchase_taxes_input = params.get('purchase_taxes') or params.get('purchase_tax')
            if purchase_taxes_input:
                if not isinstance(purchase_taxes_input, list):
                    purchase_taxes_input = [purchase_taxes_input]
                for tax_val in purchase_taxes_input:
                    tax_record = None
                    if isinstance(tax_val, (int, float)):
                        tax_record = env['account.tax'].search([('amount', '=', float(tax_val)), ('type_tax_use', '=', 'purchase')], limit=1)
                    elif isinstance(tax_val, str):
                        try:
                            val_float = float(tax_val.replace('%', '').strip())
                            tax_record = env['account.tax'].search([('amount', '=', val_float), ('type_tax_use', '=', 'purchase')], limit=1)
                        except ValueError:
                            pass
                        if not tax_record:
                            tax_record = env['account.tax'].search([('name', 'ilike', tax_val), ('type_tax_use', '=', 'purchase')], limit=1)
                    if tax_record:
                        purchase_tax_ids.append(tax_record.id)
            if purchase_tax_ids:
                vals['supplier_taxes_id'] = [(6, 0, purchase_tax_ids)]

            product_tmpl = env['product.template'].create(vals)
            product = product_tmpl.product_variant_id

            if qty_on_hand > 0 and product:
                try:
                    warehouse = env['stock.warehouse'].search([], limit=1)
                    if warehouse:
                        location = warehouse.lot_stock_id
                        env['stock.quant'].with_context(inventory_mode=True).create({
                            'product_id': product.id,
                            'location_id': location.id,
                            'inventory_quantity': qty_on_hand,
                        }).action_apply_inventory()
                except Exception as ex:
                    _logger.warning(f"Could not apply initial inventory: {ex}")

            if custom_cr:
                custom_cr.commit()

            return self._make_json_response({
                "message": "Product created successfully",
                "product_id": product.id if product else product_tmpl.id,
                "itemcode": item_code
            })

        except Exception as e:
            _logger.exception("SaaS API: Error creating product")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    @http.route('/saas_api/edit_item', type='http', auth='public', methods=['PUT', 'POST', 'OPTIONS'], csrf=False)
    def edit_item(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        # Handle RESTful routing where item_name might be passed as a query param or in path by some clients
        item_code = params.get('item_code') or params.get('reference') or params.get('name')
        
        # If it's a PUT request to /saas_api/edit_item/SKU-15561, the framework might not pass it directly to kwargs 
        # unless we define a route like /saas_api/edit_item/<string:item_code>. Since we just want to replace
        # the flutter endpoint, let's also extract from the URL if needed.
        # But for simplicity, we will just use the params dict as Flutter can send it in body.

        if not item_code:
            # Let's try to see if it's in the item_name
            item_code = params.get('item_name')
        
        if not item_code:
            return self._make_json_response({"error": "Missing required field item_code"}, status=400)

        item_name = params.get('item_name')
        description = params.get('description')
        stock_uom = params.get('stock_uom') or params.get('uom')
        
        price = params.get('price') or params.get('sales_price') or params.get('list_price')
        price = float(price) if price is not None else None
        
        buying_price = params.get('buying_price') or params.get('cost') or params.get('standard_price')
        buying_price = float(buying_price) if buying_price is not None else None
        
        barcode = params.get('barcode')
        
        track_inv_raw = params.get('track_inventory')
        
        env, custom_cr = self._get_env(user_id=uid)
        try:
            product = env['product.product'].search([
                '|', ('default_code', '=', item_code), ('name', '=', item_code)
            ], limit=1)
            
            if not product:
                return self._make_json_response({"error": f"Product not found with code/name: {item_code}"}, status=404)
            
            vals = {}
            if item_name:
                vals['name'] = item_name
            if description:
                vals['description_sale'] = description
            if price is not None:
                vals['list_price'] = price
            if buying_price is not None:
                vals['standard_price'] = buying_price
            if barcode:
                vals['barcode'] = barcode
                
            if stock_uom:
                uom = env['uom.uom'].search([('name', '=', stock_uom)], limit=1)
                if uom:
                    vals['uom_id'] = uom.id
                    
            if track_inv_raw is not None:
                track_inv = True
                if isinstance(track_inv_raw, str):
                    track_inv = track_inv_raw.lower() in ['yes', 'true', '1']
                else:
                    track_inv = bool(track_inv_raw)
                vals['is_storable'] = track_inv
                if track_inv:
                    vals['type'] = 'consu'
                    
            product.write(vals)
            
            if custom_cr:
                custom_cr.commit()
                
            return self._make_json_response({
                "message": "Product updated successfully",
                "product_id": product.id,
                "itemcode": product.default_code
            })

        except Exception as e:
            _logger.exception("SaaS API: Error updating product")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    @http.route(['/saas_api/get_sales_invoice', '/saas_api/sales_invoices'], type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def get_sales_invoice(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        # Optional filters from the request body
        limit = int(params.get('limit', 100))
        page = int(params.get('page', 1))
        offset = (page - 1) * limit

        # Date range filters (ISO strings e.g. "2026-01-01")
        date_from = params.get('date_from') or params.get('from_date')
        date_to = params.get('date_to') or params.get('to_date')

        # Customer filter
        customer_filter = params.get('customer') or params.get('customer_name')

        # Invoice name / number filter
        invoice_name = params.get('name') or params.get('invoice_name')

        env, custom_cr = self._get_env(user_id=uid)
        try:
            domain = [
                ('move_type', '=', 'out_invoice'),
                ('state', '=', 'posted'),
            ]

            if date_from:
                domain.append(('invoice_date', '>=', date_from))
            if date_to:
                domain.append(('invoice_date', '<=', date_to))
            if customer_filter:
                domain.append(('partner_id.name', 'ilike', customer_filter))
            if invoice_name:
                domain.append(('name', 'ilike', invoice_name))

            invoices = env['account.move'].search(domain, limit=limit, offset=offset, order='invoice_date desc, id desc')

            result = []
            for inv in invoices:
                # Parse posting_date and posting_time from invoice_date / invoice_date_due
                inv_date = inv.invoice_date
                posting_date = str(inv_date) if inv_date else ""

                # invoice_date is a Date field; use create_date for posting_time
                create_dt = inv.create_date  # Datetime
                if create_dt:
                    posting_time = create_dt.strftime("%H:%M:%S")
                else:
                    posting_time = "00:00:00"

                due_date = str(inv.invoice_date_due) if inv.invoice_date_due else posting_date

                # Items: each account.move.line that is a product line
                items = []
                total_qty = 0.0
                for line in inv.invoice_line_ids:
                    # Skip tax lines and note lines (no product)
                    if line.display_type in ('line_section', 'line_note'):
                        continue
                    qty = line.quantity or 0.0
                    rate = line.price_unit or 0.0
                    amount = line.price_subtotal or 0.0
                    # Use the product name directly; line.name can include [code] prefix + description
                    if line.product_id:
                        item_name = line.product_id.name
                    else:
                        item_name = line.name or ""
                    item_code = line.product_id.default_code or "" if line.product_id else ""
                    total_qty += qty
                    items.append({
                        "item_name": item_name,
                        "item_code": item_code,
                        "qty": qty,
                        "rate": rate,
                        "amount": amount,
                    })

                # Totals
                total_excl_taxes = inv.amount_untaxed or 0.0
                total_taxes = inv.amount_tax or 0.0
                grand_total = inv.amount_total or 0.0

                # Audit: created_by / last_modified_by
                created_by = inv.create_uid.name if inv.create_uid else "Administrator"
                last_modified_by = inv.write_uid.name if inv.write_uid else created_by

                result.append({
                    "name": inv.name or "",
                    "customer": inv.partner_id.name if inv.partner_id else "",
                    "company": inv.company_id.name if inv.company_id else "",
                    "customer_name": inv.partner_id.name if inv.partner_id else "",
                    "posting_date": posting_date,
                    "posting_time": posting_time,
                    "due_date": due_date,
                    "items": items,
                    "total_qty": total_qty,
                    "total": total_excl_taxes,
                    "total_taxes_and_charges": total_taxes,
                    "grand_total": grand_total,
                    "created_by": created_by,
                    "last_modified_by": last_modified_by,
                })

            return self._make_json_response({"message": result})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching sales invoices")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /saas_api/get_customers
    # =========================================================================
    @http.route(['/saas_api/get_customers', '/saas_api/customers'], type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def get_customers(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        limit = int(params.get('limit', 500))
        search_name = params.get('name') or params.get('search') or ''

        env, custom_cr = self._get_env(user_id=uid)
        try:
            domain = [('customer_rank', '>', 0)]
            if search_name:
                domain.append(('name', 'ilike', search_name))

            partners = env['res.partner'].search(domain, limit=limit, order='name asc')

            # Fallback: if no customer_rank records, return all contacts
            if not partners and not search_name:
                partners = env['res.partner'].search([('is_company', '=', False)], limit=limit, order='name asc')

            result = []
            for p in partners:
                mobile = getattr(p, 'mobile', None) or getattr(p, 'mobile_phone', None) or ""
                result.append({
                    "name": p.name or "",
                    "customer_name": p.name or "",
                    "customer_group": "Commercial" if p.is_company else "Individual",
                    "email": p.email or "",
                    "phone": p.phone or mobile or "",
                    "street": p.street or "",
                    "city": p.city or "",
                    "country": p.country_id.name if p.country_id else "",
                    "territory": p.country_id.name if p.country_id else "All Territories",
                    "ref": p.ref or "",
                })

            return self._make_json_response({"message": result})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching customers")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /saas_api/get_warehouses
    # =========================================================================
    @http.route(['/saas_api/get_warehouses', '/saas_api/warehouses'], type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def get_warehouses(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            warehouses = env['stock.warehouse'].search([], order='name asc')

            result = []
            for wh in warehouses:
                result.append({
                    "name": wh.name or "",
                    "code": wh.code or "",
                    "company": wh.company_id.name if wh.company_id else "",
                    "address": wh.partner_id.street if wh.partner_id else "",
                    "city": wh.partner_id.city if wh.partner_id else "",
                    "country": wh.partner_id.country_id.name if wh.partner_id and wh.partner_id.country_id else "",
                })

            return self._make_json_response({"message": result})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching warehouses")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /saas_api/get_cost_centers  (analytic accounts = cost centers in Odoo)
    # =========================================================================
    @http.route(['/saas_api/get_cost_centers', '/saas_api/cost_centers'], type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def get_cost_centers(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        search_name = params.get('name') or params.get('search') or ''
        plan_name = params.get('plan') or ''  # filter by analytic plan name

        env, custom_cr = self._get_env(user_id=uid)
        try:
            domain = []
            if search_name:
                domain.append(('name', 'ilike', search_name))
            if plan_name:
                domain.append(('plan_id.name', 'ilike', plan_name))

            accounts = env['account.analytic.account'].search(domain, order='name asc')

            result = []
            for acc in accounts:
                plan = ""
                try:
                    plan = acc.plan_id.name if acc.plan_id else ""
                except Exception:
                    pass
                result.append({
                    "name": acc.name or "",
                    "code": acc.code or "",
                    "plan": plan,
                    "company": acc.company_id.name if acc.company_id else "",
                    "active": acc.active,
                })

            return self._make_json_response({"message": result})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching cost centers / analytic accounts")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /saas_api/get_item_groups & /api/resource/Item Group
    # =========================================================================
    @http.route(['/saas_api/get_item_groups', '/saas_api/item_groups', '/api/resource/Item Group'], type='http', auth='public', methods=['GET', 'POST', 'OPTIONS'], csrf=False)
    def get_item_groups(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            categories = env['product.category'].search([], order='name asc')

            result = []
            has_root = False
            for cat in categories:
                cat_name = cat.name or ""
                if cat_name == "All Item Groups":
                    has_root = True
                
                parent_name = ""
                if cat.parent_id:
                    parent_name = cat.parent_id.name or ""
                else:
                    if cat_name != "All Item Groups":
                        parent_name = "All Item Groups"

                result.append({
                    "name": cat_name,
                    "item_group_name": cat_name,
                    "parent_item_group": parent_name
                })

            if not has_root:
                result.insert(0, {
                    "name": "All Item Groups",
                    "item_group_name": "All Item Groups",
                    "parent_item_group": ""
                })

            return self._make_json_response({"data": result})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching item groups")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/resource/Tax Category
    # =========================================================================
    @http.route(['/api/resource/Tax Category'], type='http', auth='public', methods=['GET', 'OPTIONS'], csrf=False)
    def get_tax_categories_resource(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            # We fetch tax groups or taxes to act as categories
            tax_groups = env['account.tax.group'].search([])
            result = []
            for tg in tax_groups:
                result.append({
                    "name": tg.name or "",
                    "title": tg.name or ""
                })
            
            # Fallback if no tax groups
            if not result:
                result = [{"name": "VAT", "title": "VAT"}, {"name": "Standard", "title": "Standard"}]

            return self._make_json_response({"data": result})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching tax categories")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/resource/Customer Group
    # =========================================================================
    @http.route(['/api/resource/Customer Group'], type='http', auth='public', methods=['GET', 'OPTIONS'], csrf=False)
    def get_customer_groups_resource(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            # Return some static customer groups matching standard Odoo logic or static
            result = [
                {"name": "Commercial"},
                {"name": "Individual"},
                {"name": "All Customer Groups"}
            ]

            return self._make_json_response({"data": result})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching customer groups")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/method/saas_api.www.api.get_my_product_bundles
    # =========================================================================
    @http.route(['/api/method/saas_api.www.api.get_my_product_bundles'], type='http', auth='public', methods=['GET', 'OPTIONS'], csrf=False)
    def get_my_product_bundles(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            # Check for mrp.bom to return as product bundles if mrp is installed
            bundles = []
            if 'mrp.bom' in env:
                boms = env['mrp.bom'].search([('type', '=', 'phantom')])
                for bom in boms:
                    if not bom.product_tmpl_id:
                        continue
                    items = []
                    for line in bom.bom_line_ids:
                        items.append({
                            "item_code": line.product_id.default_code or str(line.product_id.id),
                            "qty": line.product_qty or 1.0
                        })
                    bundles.append({
                        "new_item_code": bom.product_tmpl_id.default_code or str(bom.product_tmpl_id.id),
                        "items": items
                    })

            # Return empty list if no bundles found to prevent 404
            return self._make_json_response({"message": bundles})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching product bundles")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/resource/Item/<item_code>
    # =========================================================================
    @http.route(['/api/resource/Item/<string:item_code>'], type='http', auth='public', methods=['PUT', 'OPTIONS'], csrf=False)
    def update_item_resource(self, item_code, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            # We need to find the product by item_code (default_code or barcode or id)
            product = env['product.product'].search([('default_code', '=', item_code)], limit=1)
            if not product:
                product = env['product.product'].search([('barcode', '=', item_code)], limit=1)
            if not product and item_code.isdigit():
                product = env['product.product'].browse(int(item_code))
                if not product.exists():
                    product = None
                    
            if not product:
                return self._make_json_response({"error": f"Product {item_code} not found"}, status=404)

            # Update fields based on params
            vals = {}
            if 'item_name' in params:
                vals['name'] = params['item_name']
            if 'description' in params:
                vals['description_sale'] = params['description']
            if 'standard_selling' in params or 'price' in params or 'list_price' in params:
                price = params.get('standard_selling') or params.get('price') or params.get('list_price')
                if price is not None:
                    vals['list_price'] = float(price)
            if 'valuation_rate' in params or 'standard_price' in params or 'cost' in params:
                cost = params.get('valuation_rate') or params.get('standard_price') or params.get('cost')
                if cost is not None:
                    vals['standard_price'] = float(cost)
            if 'disabled' in params:
                vals['active'] = not bool(params['disabled'])

            if vals:
                product.write(vals)
                if custom_cr:
                    custom_cr.commit()

            return self._make_json_response({
                "data": {
                    "name": product.default_code or str(product.id),
                    "item_name": product.name,
                    "message": "Item updated successfully"
                }
            })

        except Exception as e:
            _logger.exception(f"SaaS API: Error updating item {item_code}")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/resource/Item Price  (GET with filters, POST create, PUT update)
    # =========================================================================
    @http.route(['/api/resource/Item Price', '/api/resource/Item Price/<string:price_name>'], type='http', auth='public', methods=['GET', 'POST', 'PUT', 'OPTIONS'], csrf=False)
    def item_price_resource(self, price_name=None, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            if request.httprequest.method == 'GET':
                # Parse Frappe-style filters from query params
                filters_raw = request.httprequest.args.get('filters', '[]')
                try:
                    filters_list = json.loads(filters_raw)
                except Exception:
                    filters_list = []

                # Build Odoo domain from Frappe filters like [["item_code","=","SKU-123"]]
                # We don't have an Item Price model in Odoo, so we simulate it
                # by looking up product pricelist items
                item_code_filter = None
                price_list_filter = None
                for f in filters_list:
                    if len(f) >= 3:
                        if f[0] == 'item_code':
                            item_code_filter = f[2]
                        elif f[0] == 'price_list':
                            price_list_filter = f[2]

                # Return empty data (no matching Item Price records in Odoo)
                # This tells the Flutter app to create a new price entry instead of update
                return self._make_json_response({"data": []})

            elif request.httprequest.method in ('POST', 'PUT'):
                # Create or update a price — we map this to Odoo's pricelist items
                item_code = params.get('item_code', '')
                price_list_name = params.get('price_list', '')
                rate = float(params.get('price_list_rate', 0.0))
                uom_name = params.get('uom', '')
                is_selling = params.get('selling', 0)

                product = env['product.product'].search([('default_code', '=', item_code)], limit=1)
                if not product:
                    return self._make_json_response({"error": f"Product {item_code} not found"}, status=404)

                # Directly update the product's list_price or standard_price
                if price_list_name and 'buying' in price_list_name.lower():
                    product.standard_price = rate
                else:
                    product.list_price = rate

                if custom_cr:
                    custom_cr.commit()

                return self._make_json_response({
                    "data": {
                        "name": f"{item_code}-{price_list_name}",
                        "item_code": item_code,
                        "price_list": price_list_name,
                        "price_list_rate": rate,
                    }
                })

        except Exception as e:
            _logger.exception("SaaS API: Error handling Item Price request")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/resource/Price List
    # =========================================================================
    @http.route(['/api/resource/Price List', '/api/resource/Price List/<string:pl_name>'], type='http', auth='public', methods=['GET', 'OPTIONS'], csrf=False)
    def price_list_resource(self, pl_name=None, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            # Return two standard price lists that Odoo always has
            result = [
                {"name": "Standard Selling", "currency": "USD", "enabled": 1, "selling": 1, "buying": 0},
                {"name": "Standard Buying", "currency": "USD", "enabled": 1, "selling": 0, "buying": 1},
            ]

            # Try to get currency from company
            try:
                company = env['res.company'].search([], limit=1)
                if company and company.currency_id:
                    currency_name = company.currency_id.name
                    for r in result:
                        r["currency"] = currency_name
            except Exception:
                pass

            return self._make_json_response({"data": result})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching price lists")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/resource/Item  (POST create item via Frappe REST pattern)
    # =========================================================================
    @http.route(['/api/resource/Item'], type='http', auth='public', methods=['POST', 'GET', 'OPTIONS'], csrf=False)
    def item_resource(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        if request.httprequest.method == 'GET':
            # Redirect to products endpoint logic
            return self.get_products(**kwargs)

        # POST — create item, delegate to existing add_item logic
        return self.add_item(**kwargs)

    # =========================================================================
    # /api/method/saas_api.www.api.get_account
    # =========================================================================
    @http.route(['/api/method/saas_api.www.api.get_account'], type='http', auth='public', methods=['GET', 'OPTIONS'], csrf=False)
    def get_account(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json() if request.httprequest.method == 'POST' else request.params
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            # Fetch bank and cash journals to represent accounts
            journals = env['account.journal'].search([('type', 'in', ['bank', 'cash'])])
            accounts = []
            for j in journals:
                currency = j.currency_id.name or env.company.currency_id.name or 'USD'
                accounts.append({
                    "name": j.name,
                    "account_name": j.name,
                    "account_type": "Cash" if j.type == 'cash' else "Bank",
                    "account_currency": currency,
                    "currency": currency
                })
            

                
            return self._make_json_response({"message": accounts})

        except Exception as e:
            _logger.exception("SaaS API: Error getting accounts")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/method/saas_api.www.api.get_stock_reconciliation_with_items
    # =========================================================================
    @http.route(['/api/method/saas_api.www.api.get_stock_reconciliation_with_items'], type='http', auth='public', methods=['GET', 'OPTIONS'], csrf=False)
    def get_stock_reconciliation_with_items(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = request.httprequest.args.to_dict()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            date_from = params.get('from_date')
            date_to = params.get('to_date')

            domain = [
                ('picking_id', '=', False), 
                ('state', '=', 'done'),
                '|',
                ('location_id.usage', '=', 'inventory'),
                ('location_dest_id.usage', '=', 'inventory')
            ]
            
            if date_from:
                domain.append(('date', '>=', date_from))
            if date_to:
                domain.append(('date', '<=', date_to))

            moves = env['stock.move'].search(domain, order='date desc')
            
            grouped = {}
            for move in moves:
                date_str = str(move.date.date() if move.date else move.create_date.date())
                if date_str not in grouped:
                    grouped[date_str] = {
                        "name": f"RECON-{date_str}",
                        "company": move.company_id.name if move.company_id else "",
                        "posting_date": date_str,
                        "purpose": "Stock Reconciliation",
                        "cost_center": "",
                        "difference_amount": 0.0,
                        "items": []
                    }
                
                qty_diff = move.product_uom_qty
                if move.location_dest_id.usage == 'inventory':
                    qty_diff = -qty_diff
                    warehouse = move.location_id.complete_name
                else:
                    warehouse = move.location_dest_id.complete_name

                val_rate = move.product_id.standard_price or 0.0
                amt_diff = qty_diff * val_rate

                grouped[date_str]["difference_amount"] += amt_diff
                grouped[date_str]["items"].append({
                    "item_code": move.product_id.default_code or str(move.product_id.id),
                    "item_name": move.product_id.name,
                    "current_qty": 0.0,
                    "qty": qty_diff,
                    "valuation_rate": val_rate,
                    "warehouse": warehouse,
                    "quantity_difference": qty_diff,
                    "amount_difference": amt_diff
                })

            return self._make_json_response({"message": list(grouped.values())})

        except Exception as e:
            _logger.exception("SaaS API: Error getting stock reconciliations")
            if custom_cr: custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr: custom_cr.close()

    # =========================================================================
    # /api/resource/Stock Reconciliation  (POST create)
    # =========================================================================
    @http.route(['/api/resource/Stock Reconciliation'], type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def stock_reconciliation_resource(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            items = params.get('items', [])
            if not items:
                return self._make_json_response({"error": "No items provided for reconciliation"}, status=400)

            results = []
            for item in items:
                item_code = item.get('item_code')
                new_qty = item.get('qty')
                warehouse = item.get('warehouse')

                if not item_code or new_qty is None:
                    continue

                new_qty = float(new_qty)

                product = env['product.product'].search([('default_code', '=', item_code)], limit=1)
                if not product:
                    product = env['product.product'].search([('name', 'ilike', item_code)], limit=1)
                if not product:
                    continue

                location = None
                if warehouse:
                    location = env['stock.location'].search([
                        ('complete_name', 'ilike', warehouse),
                        ('usage', '=', 'internal')
                    ], limit=1)
                if not location:
                    location = env['stock.location'].search([('usage', '=', 'internal')], limit=1)
                if not location:
                    continue

                quant = env['stock.quant'].search([
                    ('product_id', '=', product.id),
                    ('location_id', '=', location.id),
                ], limit=1)

                current_qty = quant.quantity if quant else 0
                diff = new_qty - current_qty

                if diff != 0:
                    # In Odoo 15+, inventory adjustments are done via inventory_quantity
                    if not quant:
                        quant = env['stock.quant'].create({
                            'product_id': product.id,
                            'location_id': location.id,
                            'inventory_quantity': new_qty,
                        })
                    else:
                        quant.inventory_quantity = new_qty
                    quant.action_apply_inventory()
                    results.append({"item_code": item_code, "adjusted": diff})

            if custom_cr:
                custom_cr.commit()

            return self._make_json_response({
                "data": {
                    "name": "RECON-" + fields.Datetime.now().strftime("%Y%m%d%H%M%S"),
                    "docstatus": 1,
                    "message": f"Adjusted {len(results)} items"
                }
            })

        except Exception as e:
            _logger.exception("SaaS API: Error in Stock Reconciliation")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/resource/Stock Entry  (POST create)
    # =========================================================================
    @http.route(['/api/resource/Stock Entry', '/api/resource/Stock Entry/<string:name>'], type='http', auth='public', methods=['POST', 'GET', 'PUT', 'OPTIONS'], csrf=False)
    def stock_entry_resource(self, name=None, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = {}
        if request.httprequest.method in ['POST', 'PUT']:
            params = self._get_request_json()
        params.update(request.httprequest.args.to_dict())

        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            if request.httprequest.method == 'PUT':
                if not name:
                    return self._make_json_response({"error": "Name required for PUT"}, status=400)
                docstatus = params.get('docstatus')
                if docstatus == 2:
                    picking = env['stock.picking'].search([('name', '=', name)], limit=1)
                    if picking:
                        picking.action_cancel()
                        if custom_cr: custom_cr.commit()
                        return self._make_json_response({"message": "Cancelled"})
                return self._make_json_response({"error": "Invalid update"}, status=400)

            if request.httprequest.method == 'GET':
                if name:
                    # Get single entry detail
                    picking = env['stock.picking'].search([('name', '=', name)], limit=1)
                    if not picking:
                        return self._make_json_response({"error": "Not found"}, status=404)
                        
                    items = []
                    for move in picking.move_ids_without_package:
                        items.append({
                            "item_code": move.product_id.default_code or str(move.product_id.id),
                            "item_name": move.product_id.name,
                            "qty": move.product_uom_qty,
                            "uom": move.product_uom.name if move.product_uom else 'Nos',
                            "source_warehouse": move.location_id.complete_name,
                            "target_warehouse": move.location_dest_id.complete_name,
                        })
                    res = {
                        "name": picking.name,
                        "stock_entry_type": "Material Transfer",
                        "from_warehouse": picking.location_id.complete_name,
                        "to_warehouse": picking.location_dest_id.complete_name,
                        "posting_date": str(getattr(picking, 'date_done', False) or getattr(picking, 'scheduled_date', False) or picking.create_date),
                        "docstatus": 1 if picking.state == 'done' else (2 if picking.state == 'cancel' else 0),
                        "items": items,
                        "total_outgoing_value": 0.0,
                        "remarks": picking.note or '',
                    }
                    return self._make_json_response({"data": res})
                else:
                    # List entries
                    limit = int(params.get('limit', int(params.get('limit_page_length', 50))))
                    pickings = env['stock.picking'].search([('picking_type_id.code', '=', 'internal')], limit=limit, order='create_date desc')
                    res = []
                    for p in pickings:
                        res.append({
                            "name": p.name,
                            "stock_entry_type": "Material Transfer",
                            "from_warehouse": p.location_id.complete_name,
                            "to_warehouse": p.location_dest_id.complete_name,
                            "posting_date": str(getattr(p, 'date_done', False) or getattr(p, 'scheduled_date', False) or p.create_date),
                            "docstatus": 1 if p.state == 'done' else (2 if p.state == 'cancel' else 0),
                            "total_outgoing_value": 0.0,
                            "remarks": p.note or '',
                        })
                    return self._make_json_response({"data": res})

            items = params.get('items', [])
            stock_entry_type = params.get('stock_entry_type', '')
            from_warehouse = params.get('from_warehouse', '')
            to_warehouse = params.get('to_warehouse', '')

            if not items:
                return self._make_json_response({"error": "No items provided"}, status=400)

            # Resolve global locations or fallback to item-level locations
            global_source = None
            if from_warehouse:
                global_source = env['stock.location'].search([
                    ('complete_name', 'ilike', from_warehouse), ('usage', '=', 'internal')
                ], limit=1)

            global_target = None
            if to_warehouse:
                global_target = env['stock.location'].search([
                    ('complete_name', 'ilike', to_warehouse), ('usage', '=', 'internal')
                ], limit=1)

            picking_type = env['stock.picking.type'].search([('code', '=', 'internal')], limit=1)
            if not picking_type:
                return self._make_json_response({"error": "No internal transfer operation type configured"}, status=400)

            # We need a fallback source/target if not fully defined
            fallback_source = global_source or env['stock.location'].search([('usage', '=', 'internal')], limit=1)
            fallback_target = global_target or env['stock.location'].search([('usage', '=', 'internal')], limit=1)

            move_lines = []
            for item in items:
                item_code = item.get('item_code')
                qty = float(item.get('qty', 0))
                s_ware = item.get('s_warehouse') or item.get('source_warehouse')
                t_ware = item.get('t_warehouse') or item.get('target_warehouse')

                if not item_code or qty <= 0:
                    continue

                product = env['product.product'].search([('default_code', '=', item_code)], limit=1)
                if not product:
                    product = env['product.product'].search([('name', 'ilike', item_code)], limit=1)
                if not product:
                    continue

                src = fallback_source
                if s_ware:
                    s_loc = env['stock.location'].search([('complete_name', 'ilike', s_ware), ('usage', '=', 'internal')], limit=1)
                    if s_loc: src = s_loc

                dst = fallback_target
                if t_ware:
                    t_loc = env['stock.location'].search([('complete_name', 'ilike', t_ware), ('usage', '=', 'internal')], limit=1)
                    if t_loc: dst = t_loc

                if not src or not dst:
                    continue

                move_lines.append((0, 0, {
                    'product_id': product.id,
                    'product_uom_qty': qty,
                    'product_uom': product.uom_id.id,
                    'location_id': src.id,
                    'location_dest_id': dst.id,
                }))

            if not move_lines:
                return self._make_json_response({"error": "Could not resolve products or locations for items"}, status=400)

            picking = env['stock.picking'].create({
                'picking_type_id': picking_type.id,
                'location_id': global_source.id if global_source else fallback_source.id,
                'location_dest_id': global_target.id if global_target else fallback_target.id,
                'origin': f'POS {stock_entry_type}',
                'move_ids': move_lines,
            })

            picking.action_confirm()
            for move in picking.move_ids:
                move.quantity = move.product_uom_qty
            picking.button_validate()

            if custom_cr:
                custom_cr.commit()

            return self._make_json_response({
                "data": {
                    "name": picking.name,
                    "docstatus": 1,
                    "message": "Stock Entry created successfully"
                }
            })

        except Exception as e:
            _logger.exception("SaaS API: Error creating Stock Entry")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()


    # =========================================================================
    # /api/resource/Purchase Invoice  (POST create, GET list)
    # =========================================================================
    @http.route(['/api/resource/Purchase Invoice', '/api/resource/Purchase Invoice/<string:inv_name>'], type='http', auth='public', methods=['POST', 'GET', 'OPTIONS'], csrf=False)
    def purchase_invoice_resource(self, inv_name=None, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            if request.httprequest.method == 'GET':
                # List purchase invoices — delegate to get_purchases
                return self.get_purchases(**kwargs)

            # POST — create a purchase invoice (vendor bill)
            supplier_name = params.get('supplier', '')
            company_name = params.get('company', '')
            posting_date = params.get('posting_date', fields.Date.today())
            due_date = params.get('due_date', posting_date)
            items = params.get('items', [])
            docstatus = params.get('docstatus', 0)
            set_warehouse = params.get('set_warehouse', '')

            if not items:
                return self._make_json_response({"error": "No items provided"}, status=400)

            # Find or create supplier partner
            supplier = env['res.partner'].search([
                '|', ('name', '=', supplier_name), ('name', 'ilike', supplier_name)
            ], limit=1)
            if not supplier:
                supplier = env['res.partner'].create({
                    'name': supplier_name,
                    'supplier_rank': 1,
                })
                if custom_cr:
                    custom_cr.commit()

            # Find company
            company = env['res.company'].search([('name', 'ilike', company_name)], limit=1)
            if not company:
                company = env['res.company'].search([], limit=1)

            # Build purchase order lines
            po_lines = []
            for item in items:
                item_code = item.get('item_code', '')
                qty = float(item.get('qty', 1))
                rate = float(item.get('rate', 0))

                product = env['product.product'].search([('default_code', '=', item_code)], limit=1)
                if not product:
                    product = env['product.product'].search([('name', 'ilike', item_code)], limit=1)

                if product:
                    po_lines.append((0, 0, {
                        'product_id': product.id,
                        'product_qty': qty,
                        'price_unit': rate,
                        'name': product.name,
                    }))
                else:
                    # Purchase order line needs a product, so if none is found we must create one or skip
                    # ERPNext allows non-product items, but Odoo PO strictly requires product_id for most flows.
                    # Let's create a generic consumable product if not found
                    product = env['product.product'].create({
                        'name': item_code,
                        'type': 'consu',
                        'default_code': item_code,
                        'purchase_ok': True,
                    })
                    po_lines.append((0, 0, {
                        'product_id': product.id,
                        'product_qty': qty,
                        'price_unit': rate,
                        'name': item_code,
                    }))

            # Create Purchase Order
            po_vals = {
                'partner_id': supplier.id,
                'company_id': company.id,
                'date_order': posting_date,
                'order_line': po_lines,
            }

            po = env['purchase.order'].create(po_vals)

            # Process the PO all the way to Paid
            if docstatus == 1:
                try:
                    # 1. Confirm PO
                    po.button_confirm()

                    # 2. Receive Products
                    for picking in po.picking_ids:
                        if picking.state in ['cancel', 'done']:
                            continue
                            
                        # Set quantities for Odoo 17/18/19
                        for move in picking.move_ids:
                            move.quantity = move.product_uom_qty
                            if hasattr(move, 'picked'):
                                move.picked = True
                                
                        for move_line in picking.move_ids.mapped('move_line_ids'):
                            if hasattr(move_line, 'quantity_product_uom'):
                                move_line.quantity = move_line.quantity_product_uom
                            else:
                                move_line.quantity = move_line.product_uom_qty
                                
                        picking.with_context(skip_immediate=True, skip_backorder=True).button_validate()

                    # 3. Create Vendor Bill
                    po.action_create_invoice()
                    bill = po.invoice_ids[0] if po.invoice_ids else None
                    
                    if bill:
                        bill.invoice_date = posting_date
                        bill.action_post()
                        
                        # 4. Pay the Bill
                        journal = env['account.journal'].search([
                            ('type', 'in', ['bank', 'cash']),
                            ('company_id', '=', bill.company_id.id)
                        ], limit=1)
                        
                        if journal:
                            payment_register = env['account.payment.register'].with_context(
                                active_model='account.move', 
                                active_ids=bill.ids
                            ).create({
                                'journal_id': journal.id,
                                'payment_date': posting_date,
                            })
                            payment_register.action_create_payments()
                        
                        # 5. Set custom status Fully BILLED
                        po.write({'state': 'fully_billed'})

                except Exception as e:
                    _logger.warning(f"SaaS API: Could not complete PO processing: {e}")

            if custom_cr:
                custom_cr.commit()

            return self._make_json_response({
                "data": {
                    "name": po.name or str(po.id),
                    "docstatus": 1 if po.state in ['purchase', 'done', 'fully_billed'] else 0,
                    "message": "Purchase Order created successfully"
                }
            })

        except Exception as e:
            _logger.exception("SaaS API: Error handling Purchase Invoice")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.c    # =========================================================================
    # /api/resource/Payment Entry  (GET/POST)
    # =========================================================================
    @http.route(['/api/resource/Payment Entry', '/api/resource/Payment Entry/<string:payment_name>'], type='http', auth='public', methods=['POST', 'GET', 'OPTIONS'], csrf=False)
    def payment_entry_resource(self, payment_name=None, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = {}
        if request.httprequest.method in ['POST', 'PUT']:
            params = self._get_request_json()
        params.update(request.httprequest.args.to_dict())

        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        
        try:
            if request.httprequest.method == 'GET':
                limit = int(params.get('limit', 100))
                page = int(params.get('page', 1))
                offset = (page - 1) * limit
                
                domain = []
                if payment_name:
                    domain.append(('name', '=', payment_name))
                
                domain.append(('payment_type', '=', 'inbound'))
                
                payments = env['account.payment'].search(domain, limit=limit, offset=offset, order='date desc, id desc')
                
                result = []
                for p in payments:
                    result.append({
                        "name": p.name,
                        "payment_type": "Receive" if p.payment_type == "inbound" else "Pay",
                        "party_type": "Customer" if p.partner_type == "customer" else "Supplier",
                        "party": p.partner_id.id if p.partner_id else "",
                        "party_name": p.partner_id.name if p.partner_id else "",
                        "paid_to": p.journal_id.name if p.journal_id else "",
                        "paid_amount": p.amount,
                        "received_amount": p.amount,
                        "reference_no": p.memo or "",
                        "reference_date": str(p.date),
                        "remarks": p.memo or "",
                        "docstatus": 1 if p.state == 'posted' else 0,
                    })
                
                if custom_cr:
                    custom_cr.commit()
                return self._make_json_response({"message": result, "data": result})

            elif request.httprequest.method == 'POST':
                from odoo import fields
                
                party_name = params.get('party', params.get('party_name', ''))
                paid_amount = float(params.get('paid_amount', 0))
                received_amount = float(params.get('received_amount', paid_amount))
                reference_no = params.get('reference_no', '')
                remarks = params.get('remarks', 'Payment from POS')
                docstatus = int(params.get('docstatus', 0))
                paid_to = params.get('paid_to', '')
                payment_date = params.get('reference_date', fields.Date.context_today(env.user))
                references = params.get('references', [])

                partner = env['res.partner'].search([
                    '|', ('name', '=', party_name), ('name', 'ilike', party_name)
                ], limit=1)
                if not partner and str(party_name).isdigit():
                    partner = env['res.partner'].browse(int(party_name))
                    
                if not partner:
                    return self._make_json_response({"error": f"Customer '{party_name}' not found"}, status=404)

                journal = None
                if paid_to:
                    journal = env['account.journal'].search([
                        ('name', 'ilike', paid_to), ('type', 'in', ['bank', 'cash'])
                    ], limit=1)
                if not journal:
                    journal = env['account.journal'].search([('type', '=', 'cash')], limit=1)
                if not journal:
                    journal = env['account.journal'].search([('type', 'in', ['bank', 'cash'])], limit=1)

                if not journal:
                    return self._make_json_response({"error": "No cash/bank journal found"}, status=400)

                payment_vals = {
                    'payment_type': 'inbound',
                    'partner_type': 'customer',
                    'partner_id': partner.id,
                    'journal_id': journal.id,
                    'amount': paid_amount,
                    'date': payment_date,
                    'memo': reference_no or remarks,
                }

                payment = env['account.payment'].create(payment_vals)

                if docstatus == 1:
                    payment.action_post()
                    
                    if references:
                        for ref in references:
                            ref_doctype = ref.get('reference_doctype')
                            ref_name = ref.get('reference_name')
                            if ref_doctype == 'Sales Invoice' and ref_name:
                                invoice = env['account.move'].search([
                                    ('name', '=', ref_name), 
                                    ('move_type', '=', 'out_invoice'),
                                    ('state', '=', 'posted')
                                ], limit=1)
                                
                                if invoice:
                                    payment_lines = payment.line_ids.filtered(lambda line: line.account_id.account_type in ('asset_receivable', 'liability_payable') and not line.reconciled)
                                    invoice_lines = invoice.line_ids.filtered(lambda line: line.account_id.account_type in ('asset_receivable', 'liability_payable') and not line.reconciled)
                                    if payment_lines and invoice_lines:
                                        (payment_lines + invoice_lines).reconcile()

                if custom_cr:
                    custom_cr.commit()

                return self._make_json_response({
                    "data": {
                        "name": payment.name or str(payment.id),
                        "docstatus": 1 if payment.state == 'posted' else 0,
                        "message": "Payment Entry created successfully"
                    }
                })

        except Exception as e:
            _logger.exception("SaaS API: Error in Payment Entry")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/resource/Supplier  (GET list)
    # =========================================================================
    @http.route(['/api/resource/Supplier'], type='http', auth='public', methods=['GET', 'POST', 'OPTIONS'], csrf=False)
    def supplier_resource(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            if request.httprequest.method == 'POST':
                supplier_name = params.get('supplier_name') or params.get('name') or params.get('supplier')
                if not supplier_name:
                    return self._make_json_response({"error": "Supplier name is required"}, status=400)
                
                partner = env['res.partner'].create({
                    'name': supplier_name,
                    'supplier_rank': 1,
                    'is_company': params.get('supplier_type') != 'Individual'
                })
                if custom_cr:
                    custom_cr.commit()
                return self._make_json_response({
                    "data": {
                        "name": partner.name,
                        "supplier_name": partner.name
                    }
                })

            suppliers = env['res.partner'].search([('supplier_rank', '>', 0)])
            result = []
            for s in suppliers:
                result.append({
                    "name": s.name,
                    "supplier_name": s.name,
                    "supplier_type": "Company" if s.is_company else "Individual",
                })

            return self._make_json_response({"data": result})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching suppliers")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/resource/Bin  (GET warehouse stock levels)
    # =========================================================================
    @http.route(['/api/resource/Bin'], type='http', auth='public', methods=['GET', 'OPTIONS'], csrf=False)
    def bin_resource(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            # Parse Frappe-style filters
            filters_raw = request.httprequest.args.get('filters', '[]')
            warehouse_name = None
            try:
                filters_list = json.loads(filters_raw)
                for f in filters_list:
                    if len(f) >= 3 and f[0] == 'warehouse':
                        warehouse_name = f[2]
            except Exception:
                pass

            # Build domain for stock.quant
            domain = [('quantity', '!=', 0)]
            if warehouse_name:
                location = env['stock.location'].search([('complete_name', 'ilike', warehouse_name)], limit=1)
                if location:
                    domain.append(('location_id', '=', location.id))

            quants = env['stock.quant'].search(domain)

            result = []
            seen_items = {}
            for q in quants:
                item_code = q.product_id.default_code or str(q.product_id.id)
                if item_code in seen_items:
                    seen_items[item_code]['actual_qty'] += q.quantity
                    seen_items[item_code]['projected_qty'] += q.quantity
                else:
                    seen_items[item_code] = {
                        "item_code": item_code,
                        "actual_qty": q.quantity,
                        "projected_qty": q.quantity,
                        "reserved_qty": q.reserved_quantity if hasattr(q, 'reserved_quantity') else 0,
                        "ordered_qty": 0,
                    }

            result = list(seen_items.values())
            return self._make_json_response({"data": result})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching stock bins")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/resource/Sales Invoice  (GET lookup by reference)
    # =========================================================================
    @http.route(['/api/resource/Sales Invoice'], type='http', auth='public', methods=['GET', 'POST', 'OPTIONS'], csrf=False)
    def sales_invoice_resource(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            if request.httprequest.method == 'POST':
                # Delegate to make_sale for creating invoices
                return self.make_sale(**kwargs)

            # GET — lookup by Frappe filters
            filters_raw = request.httprequest.args.get('filters', '[]')
            ref_value = None
            try:
                filters_list = json.loads(filters_raw)
                for f in filters_list:
                    if len(f) >= 3 and f[0] == 'reference_number':
                        ref_value = f[2]
            except Exception:
                pass

            limit = int(request.httprequest.args.get('limit', 20))

            domain = [('move_type', '=', 'out_invoice')]
            if ref_value:
                domain.append(('ref', '=', ref_value))

            invoices = env['account.move'].search(domain, limit=limit, order='create_date desc')

            result = []
            for inv in invoices:
                result.append({
                    "name": inv.name,
                    "customer": inv.partner_id.name if inv.partner_id else '',
                    "posting_date": str(inv.invoice_date or inv.date),
                    "grand_total": inv.amount_total,
                    "status": inv.state,
                })

            return self._make_json_response({"data": result})

        except Exception as e:
            _logger.exception("SaaS API: Error handling Sales Invoice resource")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/resource/Product Bundle  (POST create, PUT update)
    # =========================================================================
    @http.route(['/api/resource/Product Bundle', '/api/resource/Product Bundle/<string:bundle_name>'], type='http', auth='public', methods=['POST', 'PUT', 'OPTIONS'], csrf=False)
    def product_bundle_resource(self, bundle_name=None, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            new_item_code = params.get('new_item_code', bundle_name or '')
            items = params.get('items', [])

            if not new_item_code:
                return self._make_json_response({"error": "Missing new_item_code"}, status=400)

            # Find the parent product
            parent_product = env['product.product'].search([('default_code', '=', new_item_code)], limit=1)
            if not parent_product:
                parent_product = env['product.product'].search([('name', 'ilike', new_item_code)], limit=1)
            if not parent_product:
                return self._make_json_response({"error": f"Product '{new_item_code}' not found"}, status=404)

            # Check if mrp module is installed
            if 'mrp.bom' not in env:
                # Fallback: just return success without creating BOM
                return self._make_json_response({
                    "data": {
                        "name": new_item_code,
                        "message": "Product Bundle saved (no MRP module — BOM not created)"
                    }
                })

            # Find or create BOM
            bom = env['mrp.bom'].search([
                ('product_tmpl_id', '=', parent_product.product_tmpl_id.id),
                ('type', '=', 'phantom'),
            ], limit=1)

            bom_lines = []
            for item in items:
                child_code = item.get('item_code', '')
                qty = float(item.get('qty', 1))
                child = env['product.product'].search([('default_code', '=', child_code)], limit=1)
                if child:
                    bom_lines.append((0, 0, {
                        'product_id': child.id,
                        'product_qty': qty,
                    }))

            if bom:
                # Update: clear old lines and replace
                bom.bom_line_ids.unlink()
                bom.write({'bom_line_ids': bom_lines})
            else:
                # Create new BOM
                bom = env['mrp.bom'].create({
                    'product_tmpl_id': parent_product.product_tmpl_id.id,
                    'type': 'phantom',
                    'bom_line_ids': bom_lines,
                })

            if custom_cr:
                custom_cr.commit()

            return self._make_json_response({
                "data": {
                    "name": new_item_code,
                    "bom_id": bom.id,
                    "message": "Product Bundle saved successfully"
                }
            })

        except Exception as e:
            _logger.exception("SaaS API: Error handling Product Bundle")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /saas_api/stock_adjustment  (POST — adjust stock levels)
    # =========================================================================
    @http.route('/saas_api/stock_adjustment', type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def stock_adjustment(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            item_code = params.get('item_code', '')
            new_qty = params.get('qty')
            warehouse = params.get('warehouse', '')
            reason = params.get('reason', 'Stock adjustment from POS')

            if not item_code or new_qty is None:
                return self._make_json_response({"error": "Missing item_code or qty"}, status=400)

            new_qty = float(new_qty)

            # Find the product
            product = env['product.product'].search([('default_code', '=', item_code)], limit=1)
            if not product:
                product = env['product.product'].search([('name', 'ilike', item_code)], limit=1)
            if not product:
                return self._make_json_response({"error": f"Product '{item_code}' not found"}, status=404)

            # Find the stock location
            location = None
            if warehouse:
                location = env['stock.location'].search([
                    ('complete_name', 'ilike', warehouse),
                    ('usage', '=', 'internal'),
                ], limit=1)
            if not location:
                location = env['stock.location'].search([('usage', '=', 'internal')], limit=1)

            if not location:
                return self._make_json_response({"error": "No internal warehouse location found"}, status=400)

            # Get current stock
            quant = env['stock.quant'].search([
                ('product_id', '=', product.id),
                ('location_id', '=', location.id),
            ], limit=1)

            current_qty = quant.quantity if quant else 0
            diff = new_qty - current_qty

            if diff == 0:
                return self._make_json_response({
                    "message": "No adjustment needed — stock already matches",
                    "item_code": item_code,
                    "current_qty": current_qty,
                })

            # Use stock.quant._update_available_quantity
            env['stock.quant']._update_available_quantity(product, location, diff)

            if custom_cr:
                custom_cr.commit()

            return self._make_json_response({
                "message": "Stock adjusted successfully",
                "item_code": item_code,
                "previous_qty": current_qty,
                "new_qty": new_qty,
                "adjustment": diff,
                "warehouse": location.complete_name,
                "reason": reason,
            })

        except Exception as e:
            _logger.exception("SaaS API: Error adjusting stock")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /saas_api/stock_transfer  (POST — transfer stock between warehouses)
    # =========================================================================
    @http.route('/saas_api/stock_transfer', type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def stock_transfer(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            item_code = params.get('item_code', '')
            qty = params.get('qty')
            source_warehouse = params.get('source_warehouse', '')
            target_warehouse = params.get('target_warehouse', '')

            if not item_code or qty is None or not source_warehouse or not target_warehouse:
                return self._make_json_response({
                    "error": "Missing required fields: item_code, qty, source_warehouse, target_warehouse"
                }, status=400)

            qty = float(qty)

            # Find product
            product = env['product.product'].search([('default_code', '=', item_code)], limit=1)
            if not product:
                product = env['product.product'].search([('name', 'ilike', item_code)], limit=1)
            if not product:
                return self._make_json_response({"error": f"Product '{item_code}' not found"}, status=404)

            # Find source location
            source_loc = env['stock.location'].search([
                ('complete_name', 'ilike', source_warehouse),
                ('usage', '=', 'internal'),
            ], limit=1)
            if not source_loc:
                return self._make_json_response({"error": f"Source warehouse '{source_warehouse}' not found"}, status=404)

            # Find target location
            target_loc = env['stock.location'].search([
                ('complete_name', 'ilike', target_warehouse),
                ('usage', '=', 'internal'),
            ], limit=1)
            if not target_loc:
                return self._make_json_response({"error": f"Target warehouse '{target_warehouse}' not found"}, status=404)

            # Find internal transfer picking type
            picking_type = env['stock.picking.type'].search([
                ('code', '=', 'internal'),
            ], limit=1)
            if not picking_type:
                return self._make_json_response({"error": "No internal transfer operation type configured"}, status=400)

            # Create the internal transfer picking
            picking = env['stock.picking'].create({
                'picking_type_id': picking_type.id,
                'location_id': source_loc.id,
                'location_dest_id': target_loc.id,
                'origin': 'POS Stock Transfer',
                'move_ids': [(0, 0, {
                    'name': f"Transfer {product.name}",
                    'product_id': product.id,
                    'product_uom_qty': qty,
                    'product_uom': product.uom_id.id,
                    'location_id': source_loc.id,
                    'location_dest_id': target_loc.id,
                })],
            })

            # Confirm and validate the transfer
            picking.action_confirm()
            # Set done quantities
            for move in picking.move_ids:
                move.quantity = qty
            picking.button_validate()

            if custom_cr:
                custom_cr.commit()

            return self._make_json_response({
                "message": "Stock transfer completed successfully",
                "transfer_name": picking.name,
                "item_code": item_code,
                "qty": qty,
                "source_warehouse": source_loc.complete_name,
                "target_warehouse": target_loc.complete_name,
            })

        except Exception as e:
            _logger.exception("SaaS API: Error transferring stock")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /saas_api/get_purchases  (GET/POST — list purchase invoices)
    # =========================================================================
    @http.route([
        '/saas_api/get_purchases', 
        '/saas_api/purchases',
        '/api/method/saas_api.www.api.get_stock_purchases_with_items'
    ], type='http', auth='public', methods=['GET', 'POST', 'OPTIONS'], csrf=False)
    def get_purchases(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        
        # Merge JSON body and GET args
        params = {}
        if request.httprequest.method == 'POST':
            params = self._get_request_json()
        params.update(request.httprequest.args.to_dict())

        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        try:
            limit = int(params.get('limit', 100))
            page = int(params.get('page', 1))
            date_from = params.get('from_date') or params.get('date_from')
            date_to = params.get('to_date') or params.get('date_to')
            offset = (page - 1) * limit

            domain = []

            if date_from:
                domain.append(('date_order', '>=', date_from))
            if date_to:
                domain.append(('date_order', '<=', date_to))

            pos = env['purchase.order'].search(domain, limit=limit, offset=offset, order='date_order desc')

            result = []
            for po in pos:
                items = []
                for line in po.order_line:
                    if not line.product_id:
                        continue
                    items.append({
                        "item_name": line.product_id.name,
                        "item_code": line.product_id.default_code or str(line.product_id.id),
                        "qty": line.product_qty,
                        "rate": line.price_unit,
                        "amount": line.price_subtotal,
                    })

                result.append({
                    "name": po.name,
                    "supplier": po.partner_id.name if po.partner_id else '',
                    "company": po.company_id.name if po.company_id else '',
                    "supplier_name": po.partner_id.name if po.partner_id else '',
                    "posting_date": str(po.date_order.date() if po.date_order else ''),
                    "due_date": str(po.date_planned.date() if po.date_planned else po.date_order.date() if po.date_order else ''),
                    "items": items,
                    "total_qty": sum(i['qty'] for i in items),
                    "total": po.amount_untaxed,
                    "total_taxes_and_charges": po.amount_tax,
                    "grand_total": po.amount_total,
                    "status": po.state,
                    "created_by": po.create_uid.name if po.create_uid else '',
                    "last_modified_by": po.write_uid.name if po.write_uid else '',
                })

            return self._make_json_response({"message": result, "data": result})

        except Exception as e:
            _logger.exception("SaaS API: Error fetching purchases")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()


    # =========================================================================
    # /api/method/saas_api.www.api.get_customer_balance
    # =========================================================================
    @http.route([
        '/api/method/saas_api.www.api.get_customer_balance',
        '/saas_api/get_customer_balance'
    ], type='http', auth='public', methods=['GET', 'OPTIONS'], csrf=False)
    def get_customer_balance(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = request.httprequest.args.to_dict()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        
        try:
            customer_name = params.get('customer')
            if not customer_name:
                return self._make_json_response({"error": "customer is required"}, status=400)
            
            partner = env['res.partner'].search([
                '|', ('name', '=', customer_name), ('name', 'ilike', customer_name)
            ], limit=1)
            
            balance = 0.0
            if partner:
                amls = env['account.move.line'].search([
                    ('partner_id', '=', partner.id),
                    ('account_id.account_type', '=', 'asset_receivable'),
                    ('reconciled', '=', False),
                    ('parent_state', '=', 'posted')
                ])
                balance = sum(amls.mapped('amount_residual'))
                
            return self._make_json_response({
                "message": {
                    "balance": balance,
                    "customer": customer_name,
                    "partner_id": partner.id if partner else None
                }
            })
            
        except Exception as e:
            _logger.exception("SaaS API: Error fetching customer balance")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/method/saas_api.www.api.create_quotation
    # =========================================================================
    @http.route([
        '/api/method/saas_api.www.api.create_quotation',
        '/saas_api/create_quotation'
    ], type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def create_quotation(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = self._get_request_json()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        
        try:
            customer_name = params.get('customer') or params.get('customer_name')
            if not customer_name:
                return self._make_json_response({"error": "Customer is required"}, status=400)
                
            partner = env['res.partner'].search([
                '|', ('name', '=', customer_name), ('name', 'ilike', customer_name)
            ], limit=1)
            
            if not partner:
                return self._make_json_response({"error": f"Customer {customer_name} not found"}, status=404)
                
            order_lines = []
            for item in params.get('items', []):
                product_code = item.get('item_code')
                product = env['product.product'].search([('default_code', '=', product_code)], limit=1)
                if not product:
                    product = env['product.product'].search([('name', '=', product_code)], limit=1)
                
                if not product:
                    # fallback if product code doesn't exist
                    product = env['product.product'].search([], limit=1)
                    
                order_lines.append((0, 0, {
                    'product_id': product.id,
                    'name': item.get('item_name') or product.name,
                    'product_uom_qty': float(item.get('qty', 1)),
                    'price_unit': float(item.get('rate', 0.0)),
                }))
                
            sale_order_vals = {
                'partner_id': partner.id,
                'client_order_ref': params.get('reference_number', ''),
                'state': 'draft', # Draft = Quotation
                'order_line': order_lines,
            }
            
            # Optional: cost_center mapping to analytic_account_id if applicable
            cost_center = params.get('cost_center')
            if cost_center and hasattr(env['sale.order'], 'analytic_account_id'):
                analytic = env['account.analytic.account'].search([('name', 'ilike', cost_center)], limit=1)
                if analytic:
                    sale_order_vals['analytic_account_id'] = analytic.id
            
            order = env['sale.order'].create(sale_order_vals)
            
            if custom_cr:
                custom_cr.commit()
                
            return self._make_json_response({
                "message": {
                    "status": "success",
                    "quotation": order.name,
                    "id": order.id
                }
            })
            
        except Exception as e:
            _logger.exception("SaaS API: Error creating quotation")
            if custom_cr:
                custom_cr.rollback()
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()

    # =========================================================================
    # /api/method/saas_api.www.api.get_quotations
    # =========================================================================
    @http.route([
        '/api/method/saas_api.www.api.get_quotations',
        '/saas_api/get_quotations'
    ], type='http', auth='public', methods=['GET', 'OPTIONS'], csrf=False)
    def get_quotations(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self._make_json_response({}, status=200)

        token = request.httprequest.headers.get('Authorization')
        params = request.httprequest.args.to_dict()
        if not token:
            token = params.get('token')

        uid, login = self._verify_token(token)
        if not uid:
            return self._make_json_response({"error": "Unauthorized"}, status=401)

        env, custom_cr = self._get_env(user_id=uid)
        
        try:
            domain = [('state', 'in', ['draft', 'sent'])]
            
            orders = env['sale.order'].search(domain, limit=100, order='date_order desc')
            
            result = []
            for order in orders:
                items = []
                for line in order.order_line:
                    items.append({
                        "item_code": line.product_id.default_code or line.product_id.name,
                        "item_name": line.name or line.product_id.name,
                        "qty": line.product_uom_qty,
                        "rate": line.price_unit,
                        "amount": line.price_subtotal
                    })
                    
                result.append({
                    "status": "Draft",
                    "name": order.name,
                    "reference_number": order.client_order_ref or '',
                    "customer": order.partner_id.name if order.partner_id else '',
                    "grand_total": order.amount_total,
                    "transaction_date": str(order.date_order.date()) if order.date_order else str(order.create_date.date()),
                    "items": items
                })
                
            return self._make_json_response({
                "message": {
                    "status": "success",
                    "quotations": result
                }
            })
            
        except Exception as e:
            _logger.exception("SaaS API: Error getting quotations")
            return self._make_json_response({"error": str(e)}, status=500)
        finally:
            if custom_cr:
                custom_cr.close()
