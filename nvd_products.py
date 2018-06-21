import json
import sqlite3

db = sqlite3.connect('nvd.db')
c = db.cursor()




with open('nvd.json', 'r') as file:
    parsed = json.load(file)

affected_products = set()

for item in parsed['CVE_Items']:
#    print('CVE:', item['cve']['CVE_data_meta']['ID'])
    for vendor in item['cve']['affects']['vendor']['vendor_data']:
#        print('  Vendor:', vendor['vendor_name'])
        for product in vendor['product']['product_data']:
#            print('    Product:', product['product_name'])
            affected_products.add((vendor['vendor_name'], product['product_name']))

print('Affected products:')
for vendor, product in affected_products:
    print('--------------------------')
    print('Product:', product,'\nVendor: ', vendor)


# sql code for inserting stuff into tables
    #c.executemany('INSERT INTO product VALUES (?, ?, CURRENT_DATE)', affected_products)

db.commit()
db.close()
