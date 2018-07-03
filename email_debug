from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import sqlite3

# SQLite databases variable & cursor
db = sqlite3.connect('nvd.db')
c = db.cursor()

cve_link = ['https://nvd.nist.gov/vuln/detail/CVE-2018-11235']
cve_link_string = ''.join(cve_link)


msg = MIMEMultipart()
msg['From'] = 'oag.bvg.test@gmail.com'
msg['To'] = 'oag.sysadmin@mailinator.com'
password = '240Sparks'
msg['Subject'] = 'IT Security automated vulnerability monitoring / Système automatisé de surveillance des vulnérabilitées de Sécurité TI'

body = "Le francais suit l'anglais" \
       "<br><br>" \
       "Hello, there is a new vulnerability for your department:" \
       "<br> " \
       "<a href="+cve_link_string+">CVE-2018-11235</a>" \
       "<br>" \
       "This is an automated message, please do not respond. If you have any questions or concerns, please contact IT Security." \
       "" \
       "<br><br>" \
       "" \
       "Bonjour, il y a une nouvelle vulnérabilité pour votre département:" \
       "<br> " \
       "<a href="+cve_link_string+">CVE-2018-11235</a>" \
       "<br>" \
       "Ceci est un méssage automatisé, veuillez ne pas répondre s'il-vous-plait. Si vous avez des questions, veuillez contacté le département de Sécurité TI"

msg.attach(MIMEText(body, 'html'))
print(msg)

# SMTP server and port number. Not to be omitted.
server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
server.login(msg['From'], password)
server.sendmail(msg['From'], msg['To'], msg.as_string())
server.quit()

db.commit()
db.close()
