from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import sqlite3

cve_link_string = "www.google.com"

def send_email(to_addr, vuln_desc, cve_link_string):

    msg = MIMEMultipart()
    # sender email, password, receiver email and subject.
    msg['From'] = #enter email
    password = #enter password
    msg['To'] = to_addr
    msg['Subject'] = #subject message

    # body of email, string mixed with HTML
    body = #body with HTML convention
    msg.attach(MIMEText(body, 'html'))
    print(msg)

    # SMTP server and port number. Not to be omitted.
    server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
    server.login(msg['From'], password)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()


send_email("#email", "VULNERABILITY DESCRIPTION", cve_link_string)
