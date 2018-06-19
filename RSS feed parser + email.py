# library imports
import feedparser
# import re
# import smtplib
import sqlite3
import time
from datetime import date

# SQLite database variable & cursor
db = sqlite3.connect('nvd.db')
c = db.cursor()

# remove create table after running once
c.execute('''CREATE TABLE nvd_table (
                        hyperlink text,
                        product text,
                        date_added text)''')

# NVD RSS feed variable
d = feedparser.parse('https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml')
print("\n+++++++++++++++++++++++++++++++++++++++")
print(d['feed']['title'], 'Scanner')
print("+++++++++++++++++++++++++++++++++++++++\n")

# function for iterating through the entries and printing out how many vulns there are
def product_scan(product_name):

    # vulnerability links list
    vuln_list = []

    # counter for how many vulns per product
    count = 0
    for entry in d.entries:
        if product_name in entry.title:
            count += 1
            # here we append the hyperlinks, product names and today's date to a list so we can manipulate it later
            vuln_list.append((entry.link, entry.title))

    c.executemany('INSERT INTO nvd_table VALUES (?, ?, CURRENT_DATE)', vuln_list)

    # making it look nice
    if count == 1:
        print('===============================================================\nThere is', count, product_name,
              'related vulnerability:')
    elif count == 0:
        print('')
    else:
        print('===============================================================\nThere are', count, product_name,
              'related vulnerabilities:')

    # this for loop is for enumerating the links for each product CVE code
    for x in vuln_list:
        print(x)


# calling the function and searching for vulns based on keyword(s)
product_list = ['mysql', 'windows', 'linux', 'explorer', 'php', 'webex', 'firefox', 'norton', 'mcafee', 'symantec']
for product in product_list:
    product_scan(product)

print(db.execute('''SELECT * FROM nvd_table;'''))

db.close()
