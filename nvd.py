# library imports
import feedparser
import re
import smtplib
import sqlite3
import time
from datetime import date

# SQLite databases variable & cursor
db = sqlite3.connect('nvd.db')
c = db.cursor()


# comment out create table after running once

#c.execute('''CREATE TABLE nvd_table (
#                        hyperlink text,
#                        product text,
#                        date_added text)''')

#c2.execute('''CREATE TABLE products_table (
#                       product text,
#                       date_added text)''')

# NVD RSS feed variable
d = feedparser.parse('https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml')
print("\n+++++++++++++++++++++++++++++++++++++++")
print(d['feed']['title'], 'Scanner')
print("+++++++++++++++++++++++++++++++++++++++\n")

# function for database product names instead of hardcoding names in the code.
def read_from_db():

    read_from_db_list = []
    c.execute('SELECT product_name FROM product')
    for row in c.fetchall():
        read_from_db_list.append(row[0])

    return read_from_db_list

# function for iterating through the entries and printing out how many vulns there are
def product_scan(product_name):

    # vulnerability links list
    vuln_list = []
    title_list = []
    summary_list = []
    # counter for how many vulns per product
    count = 0
    for entry in d.entries:
        if product_name in entry.title:
            count += 1
            # here we append the hyperlinks, description(summary), product names and todays' date to a list so we can manipulate it later
            vuln_list.append((entry.link, entry.title, entry.summary))
            title_list.append([entry.title])
            summary_list.append([entry.summary])

# sql code for inserting stuff into tables
# the 'ignore' part will avoid adding duplicates so long as there is a UNIQUE column. The UNIQUE column is the one to
# not be duplicated.

        c.executemany('INSERT OR IGNORE INTO cve VALUES (?, ?, ?, CURRENT_DATE)', vuln_list)

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


for product in read_from_db():
    product_scan(product)


db.commit()
db.close()
