from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import sqlite3

cve_link_string = "www.google.com"

def send_email(to_addr, vuln_desc, cve_link_string):

    msg = MIMEMultipart()
    # sender email, password, receiver email and subject.
    msg['From'] = 'oag.bvg.test@gmail.com'
    password = '240Sparks'
    msg['To'] = to_addr
    msg['Subject'] = 'IT Security automated vulnerability monitoring / ' \
                     'Système automatisé de surveillance des vulnérabilitées de Sécurité TI'

    # body of email, string mixed with HTML
    body =  "Le francais suit l'anglais" \
            "<br><br>" \
            "Hello, there is a new vulnerability for your department." \
            "<br> " \
            "Summary of the vulnerability:"\
            "<br>"\
            "<strong>" + vuln_desc + "</strong>" \
            "<br>"\
            "<a href="+cve_link_string+">Clink this link to view the vulnerability</a>" \
            "<br>" \
            "This is an automated message, please do not respond. If you have any questions or concerns, " \
            "please contact IT Security." \
            "" \
            "<br><br><br><br>" \
            "Bonjour, il y a une nouvelle vulnérabilité pour votre département." \
            "<br>" \
            "Sommaire de la vulnérabilité: " \
            "<br>"\
            "<strong>"+ vuln_desc +"</strong>" \
            "<br>"\
            "<a href="+cve_link_string+">Cliquez sur ce lien pour voir la vulnérabilité</a>" \
            "<br>"\
            "Ceci est un méssage automatisé, veuillez ne pas répondre s'il-vous-plait. Si vous avez des questions, " \
            "veuillez contacté le département de Sécurité TI"

    msg.attach(MIMEText(body, 'html'))
    print(msg)

    # SMTP server and port number. Not to be omitted.
    server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
    server.login(msg['From'], password)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()


send_email("oag.windows@mailinator.com", "VULNERABILITY DESCRIPTION", cve_link_string)
