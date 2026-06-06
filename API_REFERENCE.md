# SaaS API — Reference Documentation

> **Base URL:** `http://<your-odoo-host>:<port>`  
> **All endpoints accept:** `POST` requests with `Content-Type: application/json`  
> **Authentication:** Pass `token` in the `Authorization` header **or** in the request body.

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [Get Products](#2-get-products)
3. [Add / Create Product](#3-add--create-product)
4. [Make a Sale](#4-make-a-sale)
5. [Get Sales Invoices](#5-get-sales-invoices)
6. [Get Customers](#6-get-customers)
7. [Get Warehouses](#7-get-warehouses)
8. [Get Cost Centers](#8-get-cost-centers)
9. [Get Item Groups](#9-get-item-groups)
10. [Error Responses](#10-error-responses)
11. [Field Mapping Reference](#11-field-mapping-reference)

---

## 1. Authentication

### `POST /saas_api/login`

Authenticates a user and returns a bearer token used in all subsequent requests.

**Headers**
```
Content-Type: application/json
```

**Request Body**
```json
{
  "usr": "admin",
  "pwd": "admin",
  "db": "your_database_name",
  "timezone": "Africa/Harare"
}
```

| Field      | Type   | Required | Description                         |
|------------|--------|----------|-------------------------------------|
| `usr`      | string | ✅       | Odoo username / login               |
| `pwd`      | string | ✅       | Odoo password                       |
| `db`       | string | ✅       | Odoo database name                  |
| `timezone` | string | ❌       | User timezone (stored for display)  |

**Response `200 OK`**
```json
{
  "message": "Logged In",
  "token": "MjphZG1pbjpzYWFzX3NlY3JldF9rZXk=",
  "token_string": "2:123456",
  "full_name": "Administrator",
  "user": {
    "first_name": "Administrator",
    "last_name": "",
    "username": "admin",
    "email": "admin@example.com",
    "warehouse": "My Company",
    "cost_center": "General",
    "default_customer": "Cash Customer",
    "customers": [ { "name": "Cash Customer", "customer_name": "Cash Customer", "customer_group": "Individual", "territory": "All Territories" } ],
    "warehouse_items": [ { "item_code": "CHAIR-001", "item_name": "Standard Chair", "stock_uom": "Units", "actual_qty": 50.0, "projected_qty": 50.0 } ],
    "time_zone": "Africa/Harare",
    "company": {
      "name": "My Company",
      "email": "info@mycompany.com",
      "website": "www.mycompany.com"
    }
  }
}
```

> **Save the `token` value** — pass it as the `Authorization` header in all future requests.

---

## 2. Get Products

### `POST /saas_api/get_products`
### `POST /saas_api/products` _(alias)_

Returns all saleable products with prices, taxes, and stock quantities per warehouse.

**Headers**
```
Content-Type: application/json
Authorization: <token>
```

**Request Body**
```json
{
  "db": "your_database_name"
}
```

**Response `200 OK`**
```json
{
  "message": {
    "products": [
      {
        "itemcode": "CHAIR-001",
        "itemname": "Standard Chair",
        "groupname": "Goods",
        "maintainstock": 1,
        "default warehouse": "My Warehouse",
        "warehouses": [
          { "warehouse": "My Warehouse", "qtyOnHand": 50.0 }
        ],
        "prices": [
          { "priceName": "Standard Buying",  "price": 15.00, "uom": "Units", "type": "buying" },
          { "priceName": "Standard Selling", "price": 25.00, "uom": "Units", "type": "selling" }
        ],
        "taxes": [
          {
            "item_tax_template": "15% VAT",
            "tax_category": "VAT",
            "valid_from": null,
            "minimum_net_rate": 15.0,
            "maximum_net_rate": 15.0
          }
        ],
        "simple_code": "CHAIR-001",
        "is_sales_item": 1,
        "uom": {
          "stock_uom": "Units",
          "conversions": [ { "uom": "Units", "conversion_factor": 1.0 } ]
        },
        "food_and_tourism_tax": 0,
        "food_tax": 0,
        "tourism_tax": 0,
        "cumulative": 0
      }
    ]
  },
  "token": "<token>"
}
```

---

## 3. Add / Create Product

### `POST /saas_api/add_item`

Creates a new product in Odoo. Supports full field mapping for type, taxes, pricing, inventory tracking, and category.

**Headers**
```
Content-Type: application/json
Authorization: <token>
```

**Request Body**
```json
{
  "db": "your_database_name",
  "item_code": "ITEM-00569",
  "item_name": "Organic Grape Juice",
  "description": "Premium fresh grape juice",
  "product_type": "Goods",
  "invoicing_policy": "Ordered quantities",
  "track_inventory": "Yes",
  "price": 3.99,
  "buying_price": 2.10,
  "qty_on_hand": 45.0,
  "stock_uom": "Units",
  "barcode": "6009876543210",
  "sales_taxes": "VAT",
  "purchase_taxes": "VAT",
  "category": "Goods"
}
```

| Field               | Type            | Required | Description                                              |
|---------------------|-----------------|----------|----------------------------------------------------------|
| `item_code`         | string          | ✅       | Internal reference / SKU                                |
| `item_name`         | string          | ✅       | Product name                                            |
| `description`       | string          | ❌       | Sales description                                       |
| `product_type`      | string          | ❌       | `"Goods"`, `"Service"`, or `"Combo"` (default: `Goods`) |
| `invoicing_policy`  | string          | ❌       | `"Ordered quantities"` or `"Delivered quantities"`       |
| `track_inventory`   | string/bool     | ❌       | `"Yes"` / `"No"` / `true` / `false`                    |
| `price`             | number          | ❌       | Sales price (list price)                                |
| `buying_price`      | number          | ❌       | Cost / standard price                                   |
| `qty_on_hand`       | number          | ❌       | Initial stock quantity to set                           |
| `stock_uom`         | string          | ❌       | Unit of measure name e.g. `"Units"`, `"kg"`             |
| `barcode`           | string          | ❌       | Product barcode                                         |
| `sales_taxes`       | string or array | ❌       | Tax name(s) e.g. `"VAT"` or `["VAT", "Tourism Tax"]`   |
| `purchase_taxes`    | string or array | ❌       | Purchase tax name(s)                                    |
| `category`          | string or int   | ❌       | Category name e.g. `"Goods"` or category ID             |

**`product_type` Mapping**

| You Send       | Odoo Value |
|----------------|-----------|
| `"Goods"`      | `consu`   |
| `"Service"`    | `service` |
| `"Combo"`      | `combo`   |

**Response `200 OK`**
```json
{
  "message": "Product created successfully",
  "product_id": 42,
  "itemcode": "ITEM-00569"
}
```

---

## 4. Make a Sale

### `POST /saas_api/make_sale`

Creates a confirmed sale order in Odoo.

**Headers**
```
Content-Type: application/json
Authorization: <token>
```

**Request Body**
```json
{
  "db": "your_database_name",
  "customer": "Grace Ndafira",
  "lines": [
    { "item_code": "CHAIR-001", "qty": 2.0, "price": 25.00 },
    { "item_code": "ITEM-00569", "qty": 1.0, "price": 3.99 }
  ]
}
```

| Field      | Type   | Required | Description                                          |
|------------|--------|----------|------------------------------------------------------|
| `customer` | string | ❌       | Customer name. Created if not found.                 |
| `lines`    | array  | ✅       | List of order lines                                  |

**Line Object**

| Field       | Type   | Required | Description                              |
|-------------|--------|----------|------------------------------------------|
| `item_code` | string | ✅       | Product reference / barcode / numeric ID |
| `qty`       | number | ✅       | Quantity ordered                         |
| `price`     | number | ✅       | Unit price                               |

**Response `200 OK`**
```json
{
  "message": "Sale created successfully",
  "sale_order_id": 12,
  "sale_order_name": "S00012"
}
```

---

## 5. Get Sales Invoices

### `POST /saas_api/get_sales_invoice`
### `POST /saas_api/sales_invoices` _(alias)_

Returns posted customer invoices (`account.move`, type `out_invoice`), newest first.

**Headers**
```
Content-Type: application/json
Authorization: <token>
```

**Request Body**
```json
{
  "db": "your_database_name",
  "limit": 100,
  "page": 1,
  "date_from": "2026-01-01",
  "date_to": "2026-12-31",
  "customer": "Grace Ndafira",
  "name": "INV/2026/00001"
}
```

| Field       | Type   | Required | Description                                     |
|-------------|--------|----------|-------------------------------------------------|
| `limit`     | int    | ❌       | Max records per page (default: `100`)           |
| `page`      | int    | ❌       | Page number for pagination (default: `1`)       |
| `date_from` | string | ❌       | Filter invoices on or after this date `YYYY-MM-DD` |
| `date_to`   | string | ❌       | Filter invoices on or before this date          |
| `customer`  | string | ❌       | Filter by customer name (partial match)         |
| `name`      | string | ❌       | Filter by invoice number (partial match)        |

**Response `200 OK`**
```json
{
  "message": [
    {
      "name": "INV/2026/00009",
      "customer": "Cash Customer",
      "company": "My Company",
      "customer_name": "Cash Customer",
      "posting_date": "2026-06-03",
      "posting_time": "08:30:55",
      "due_date": "2026-06-03",
      "items": [
        {
          "item_name": "Standard Chair",
          "item_code": "CHAIR-001",
          "qty": 3.0,
          "rate": 25.00,
          "amount": 75.00
        }
      ],
      "total_qty": 3.0,
      "total": 75.00,
      "total_taxes_and_charges": 0.0,
      "grand_total": 75.00,
      "created_by": "Administrator",
      "last_modified_by": "Administrator"
    }
  ]
}
```

---

## 6. Get Customers

### `POST /saas_api/get_customers`
### `POST /saas_api/customers` _(alias)_

Returns all customer records (`res.partner` with `customer_rank > 0`).

**Headers**
```
Content-Type: application/json
Authorization: <token>
```

**Request Body**
```json
{
  "db": "your_database_name",
  "limit": 500,
  "search": "Grace"
}
```

| Field    | Type   | Required | Description                                |
|----------|--------|----------|--------------------------------------------|
| `limit`  | int    | ❌       | Max records (default: `500`)               |
| `search` | string | ❌       | Partial name match filter                  |

**Response `200 OK`**
```json
{
  "message": [
    {
      "name": "Grace Ndafira",
      "customer_name": "Grace Ndafira",
      "customer_group": "Individual",
      "email": "grace@example.com",
      "phone": "+263771234567",
      "street": "123 Main St",
      "city": "Harare",
      "country": "Zimbabwe",
      "territory": "Zimbabwe",
      "ref": "CUST-001"
    }
  ]
}
```

---

## 7. Get Warehouses

### `POST /saas_api/get_warehouses`
### `POST /saas_api/warehouses` _(alias)_

Returns all warehouses configured in Odoo.

**Headers**
```
Content-Type: application/json
Authorization: <token>
```

**Request Body**
```json
{
  "db": "your_database_name"
}
```

**Response `200 OK`**
```json
{
  "message": [
    {
      "name": "Main Warehouse",
      "code": "WH",
      "company": "My Company",
      "address": "45 Industrial Road",
      "city": "Harare",
      "country": "Zimbabwe"
    }
  ]
}
```

---

## 8. Get Cost Centers

### `POST /saas_api/get_cost_centers`
### `POST /saas_api/cost_centers` _(alias)_

Returns all analytic accounts (called **Cost Centers** in this system). These map to `account.analytic.account` in Odoo.

**Headers**
```
Content-Type: application/json
Authorization: <token>
```

**Request Body**
```json
{
  "db": "your_database_name",
  "search": "operations",
  "plan": "Projects"
}
```

| Field    | Type   | Required | Description                                      |
|----------|--------|----------|--------------------------------------------------|
| `search` | string | ❌       | Partial name match filter                        |
| `plan`   | string | ❌       | Filter by analytic plan name (Odoo 17+)          |

**Response `200 OK`**
```json
{
  "message": [
    {
      "name": "General Operations",
      "code": "GEN-01",
      "plan": "Operations",
      "company": "My Company",
      "active": true
    }
  ]
}
```

---

## 9. Get Item Groups

### `POST /saas_api/get_item_groups`
### `POST /saas_api/item_groups` _(alias)_

Returns all product categories (called **Item Groups** in this system). These map to `product.category` in Odoo.

**Headers**
```
Content-Type: application/json
Authorization: <token>
```

**Request Body**
```json
{
  "db": "your_database_name"
}
```

**Response `200 OK`**
```json
{
  "data": [
    {
      "name": "All Item Groups",
      "item_group_name": "All Item Groups",
      "parent_item_group": ""
    },
    {
      "name": "beverages",
      "item_group_name": "beverages",
      "parent_item_group": "All Item Groups"
    }
  ]
}
```

---

## 10. Purchase Invoices (Purchases)

### `POST /api/resource/Purchase Invoice`
Creates a purchase invoice (vendor bill) in Odoo.

**Request Body**
```json
{
  "supplier": "GMB",
  "company": "My Company",
  "posting_date": "2026-06-04",
  "due_date": "2026-06-05",
  "docstatus": 1,
  "items": [
    { "item_code": "SKU-123", "qty": 5, "rate": 34 }
  ]
}
```

### `POST /saas_api/get_purchases`
Returns a list of purchase invoices. Similar to `get_sales_invoice` but for purchases.

---

## 11. Payment Entries

### `POST /api/resource/Payment Entry`
Registers a payment for a customer.

**Request Body**
```json
{
  "party": "John Doe",
  "paid_amount": 75.0,
  "received_amount": 75.0,
  "paid_to": "Cash",
  "reference_no": "Sale:abc123",
  "docstatus": 1
}
```

---

## 12. Suppliers

### `GET /api/resource/Supplier`
Returns all supplier records (partners with `supplier_rank > 0`).

---

## 13. Warehouse Stock Levels (Bins)

### `GET /api/resource/Bin`
Returns current stock levels per warehouse.

---

## 14. Stock Adjustment

### `POST /saas_api/stock_adjustment`
Adjusts the stock quantity of an item in a specific warehouse.

**Request Body**
```json
{
  "item_code": "SKU-123",
  "qty": 50,
  "warehouse": "Main Warehouse",
  "reason": "Inventory count"
}
```

---

## 15. Stock Transfer

### `POST /saas_api/stock_transfer`
Transfers stock between two internal warehouses.

**Request Body**
```json
{
  "item_code": "SKU-123",
  "qty": 10,
  "source_warehouse": "Main Warehouse",
  "target_warehouse": "Store 1"
}
```

---

## 16. Product Bundles

### `POST /api/resource/Product Bundle`
Creates or updates a Bill of Materials (kit/phantom) for a product.

**Request Body**
```json
{
  "new_item_code": "COMBO-01",
  "items": [
    { "item_code": "CHAIR-001", "qty": 4 },
    { "item_code": "TABLE-001", "qty": 1 }
  ]
}
```

---

## 17. Error Responses


All endpoints return a JSON error body with an HTTP status code on failure.

| Status | Meaning                                        |
|--------|------------------------------------------------|
| `400`  | Bad request — missing required fields          |
| `401`  | Unauthorized — invalid or missing token        |
| `500`  | Server error — Odoo exception (see `error` key)|

**Example `401`**
```json
{ "error": "Unauthorized" }
```

**Example `500`**
```json
{ "error": "Product not found in Odoo database with code: XYZ-999" }
```

---

## 11. Field Mapping Reference

### Product Type (`product_type` → Odoo `type`)

| API Value      | Odoo Value | Description                       |
|----------------|------------|-----------------------------------|
| `"Goods"`      | `consu`    | Physical storable/consumable good |
| `"Service"`    | `service`  | Service product                   |
| `"Combo"`      | `combo`    | Bundle / combo product            |

### Invoicing Policy (`invoicing_policy` → Odoo `invoice_policy`)

| API Value               | Odoo Value  |
|-------------------------|-------------|
| `"Ordered quantities"`  | `order`     |
| `"Delivered quantities"`| `delivery`  |

### Track Inventory (`track_inventory` → Odoo `is_storable`)

| API Value                     | Odoo Value |
|-------------------------------|------------|
| `"Yes"`, `"true"`, `true`, `"1"` | `True`  |
| `"No"`, `"false"`, `false`, `"0"`| `False` |

### Tax Resolution (`sales_taxes` / `purchase_taxes` → Odoo `account.tax`)

Taxes can be passed as:
- Tax name string: `"VAT"` or `"15% VAT"`
- Tax percentage: `15` or `"15%"` (matches by amount)
- Array of either: `["VAT", "Tourism Tax"]`

---

*Generated for the `saas_api` Odoo 19 custom module.*
