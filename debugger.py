# library imports
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
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
def product_db():

    read_from_db_list = []
    c.execute('SELECT product_name FROM product')
    for row in c.fetchall():
        read_from_db_list.append(row[0])

    return read_from_db_list
    # === end of product_db function === #

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
    # ===end of product_scan function=== #

for product in product_db():
    product_scan(product)

# email function
def send_email(to_addr, vuln_desc, cve_link_string):

    msg = MIMEMultipart()
    # sender email, password, receiver email and subject.
    msg['From'] = #email
    password = #password
    msg['To'] = to_addr
    msg['Subject'] = #subject

    # body of email, string mixed with HTML
    body =  #body html

    msg.attach(MIMEText(body, 'html'))
    print(msg)

    # SMTP server and port number. Not to be omitted.
    server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
    server.login(msg['From'], password)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()

    # ===end of send_email function=== #


def sql_fetcher(prod_name, dept_email):

    hyperlink = []
    summary = []
    title = []

    c.execute('SELECT hyperlink FROM cve WHERE title LIKE ? AND date_added = CURRENT_DATE', (prod_name,))
    for link in c.fetchall():
        hyperlink.append(link)
    c.execute('SELECT summary FROM cve WHERE title LIKE ? AND date_added = CURRENT_DATE', (prod_name,))
    for desc in c.fetchall():
        summary.append(desc)
    c.execute('SELECT title FROM cve WHERE title LIKE ? AND date_added = CURRENT_DATE', (prod_name,))
    for tit in c.fetchall():
        title.append(tit)
    # c.execute('SELECT hyperlink FROM cve WHERE title LIKE ', prod_name, ' AND date_added = CURRENT_DATE')
    # for link in c.fetchall():
    #     hyperlink.append(link)
    # c.execute('SELECT summary FROM cve WHERE title LIKE ', prod_name, ' AND date_added = CURRENT_DATE')
    # for desc in c.fetchall():
    #     summary.append(desc)
    # c.execute('SELECT title FROM cve WHERE title LIKE ', prod_name, ' AND date_added = CURRENT_DATE')
    # for tit in c.fetchall():
    #     title.append(tit)

    # this is the for loop where we call the send_email function and actually send emails.
    for l, t, d in zip(hyperlink, title, summary):
        if prod_name in t:
            send_email(dept_email, d, l)
        elif prod_name not in t:
            continue
    print(
        '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    print(
        '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    print(
        '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    print(
        '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    print(
        '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    for l, t, d in zip(hyperlink, title, summary):
        print(l,t,d)
print('---------------------------------------------------------------------------------------------------------------')
print('---------------------------------------------------------------------------------------------------------------')
print('---------------------------------------------------------------------------------------------------------------')
print('---------------------------------------------------------------------------------------------------------------')
print('---------------------------------------------------------------------------------------------------------------')

sql_fetcher('prodname', 'target@email')

db.commit()
db.close()
