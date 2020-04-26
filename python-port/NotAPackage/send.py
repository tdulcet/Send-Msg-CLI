import email, smtplib, ssl
import sys # duplicate import
import subprocess
import atexit # duplicate import
import os # duplicate import

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import EmailMessage
from email.mime.application import MIMEApplication

"""The purpose of this file is to fill a MIME object, possibly with sub MIME objects, with the necessary
   values/attachments/keys to send the message requested by the user.
"""

def set_main_headers(VARS, message):
    '''Set common headers in every email'''
    message["From"] = VARS["FROMEMAIL"]
    to = ", ".join(VARS["TOEMAILS"])
    message["To"] = to if to != "" else "undisclosed-recipients:;"
    if VARS["CCEMAILS"]:
        message["Cc"] = ", ".join(VARS["CCEMAILS"])
    if VARS["BCCEMAILS"]:
        message["Bcc"] = ", ".join(VARS["BCCEMAILS"])
    message["Date"] = email.utils.formatdate(localtime=True)
    message["Subject"] = VARS["SUBJECT"]
    if VARS["PRIORITY"]:
        message["X-Priority"] = VARS["PRIORITY"]
    return message

def attachments(message, attachments):
    '''
    Create a MIMEApplication method with our attachment as a payload and then attach it to our main message.
    If this ever fails, try this method: https://code.activestate.com/recipes/578150-sending-non-ascii-emails-from-python-3/
    '''
    for path in attachments:
        with open(path, 'rb') as f1:
            part = MIMEApplication(
                    f1.read(),
                    name=f'{path}')
        part['Content-Disposition'] = f'attachment;' + f' filename="{path}"'
        del part["MIME-Version"]
        message.attach(part)

def messageFromSignature(signature, content_type=None):
    message = EmailMessage()
    if content_type != None:
        message['Content-Type'] = content_type
    message.set_payload(signature)
    return message

def smime(VARS):
    '''Signs message + attachments with S/MIME protocol'''
    if not len(VARS["MESSAGE"]) > 0:
        print("No message to sign")
        sys.exit(1)

    text = MIMEText(VARS["MESSAGE"])
    del text["MIME-Version"]

    temp_msg = MIMEMultipart()
    del temp_msg["MIME-Version"]
    temp_msg.attach(text)
    attachments(temp_msg, VARS["ATTACHMENTS"])

    with open("message", "w") as f1:
        f1.write(str(temp_msg))
    atexit.register(lambda x: os.remove(x), "message")

    cert_sig = subprocess.check_output("openssl cms -sign -in message -signer "+VARS["CLIENTCERT"],shell=True)

    message = email.message_from_bytes(cert_sig)
    set_main_headers(VARS, message)
    return message

def pgp(VARS, FROMADDRESS):
    '''Signs message + attachments with PGP key'''
    if not len(VARS["MESSAGE"]) > 0:
        print("No message to sign")
        sys.exit(1)

    message = MIMEMultipart(_subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
    basemsg = MIMEText(VARS["MESSAGE"], _charset="utf-8")
    del basemsg["MIME-Version"]
    message.attach(basemsg)
    attachments(message, VARS["ATTACHMENTS"])

    with open("message", "w") as f1:
        f1.write(str(message))
    atexit.register(lambda x: os.remove(x), "message")

    p = subprocess.Popen("gpg --pinentry-mode loopback --batch -o - -ab -u \""+FROMADDRESS+"\" --passphrase-fd 0 message", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pgp_sig = p.communicate(bytes(VARS["PASSPHRASE"], "utf-8"))[0].decode()
    signmsg = messageFromSignature(pgp_sig, 'application/pgp-signature; name="signature.asc"')
    signmsg['Content-Disposition'] = 'attachment; filename="signature.asc"'
    set_main_headers(VARS, message)
    message.attach(signmsg)
    return message

def send_normal(VARS):
    '''Sends (does not sign) a message'''
    mime_text = MIMEText(VARS["MESSAGE"], "plain")
    del mime_text["MIME-Version"]

    # Attachments require a multipart object; else, just a mimetext object.
    if VARS["ATTACHMENTS"]:
        message = MIMEMultipart()
        message.attach(mime_text)

        set_main_headers(VARS, message)
        attachments(message, VARS["ATTACHMENTS"])
    else:
        message = mime_text
        set_main_headers(VARS, message)
    return message

def port465(VARS, message, PORT=465):
    '''Log in to server using secure context from the onset and send email. Port 465'''
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(VARS["SMTP"], PORT, context=context) as server:
        if VARS["VERBOSE"]:
            server.set_debuglevel(2)
        server.login(VARS["USERNAME"], VARS["PASSWORD"])
        server.send_message(message) # send_message() annoymizes BCC, rather than sendmail().
        print("Message sent")

def port587(VARS, message, PORT=587):
    '''Create an unsecured connection, then secure it, and then send email.'''
    context = ssl.create_default_context()
    with smtplib.SMTP(VARS["SMTP"], PORT) as server:
        server.starttls(context=context)
        if VARS["VERBOSE"]:
            server.set_debuglevel(2)
        server.login(VARS["USERNAME"], VARS["PASSWORD"])
        server.send_message(message) # send_message() annoymizes BCC, rather than sendmail().
        print("Message sent")

def port25(VARS, message, PORT=25):
    '''Use a local SMTP server connection to send email'''
    with smtplib.SMTP(VARS["SMTP"], PORT) as server:
        if VARS["VERBOSE"]:
            server.set_debuglevel(2)
        server.send_message(message) # send_message() annoymizes BCC, rather than sendmail().
        print("Message sent\n")

# TODO -- verify local SMTP server is handled correctly.
def sendEmail(VARS, FROMADDRESS, PORT=0):
    '''This function compiles our (optionally signed) message and calls the correct send function according to what port is entered.'''
    if VARS["DRYRUN"]:
        sys.exit()
    # S/MIME
    if VARS["CERT"]:
        message = smime(VARS)
    # PGP
    elif VARS["PASSPHRASE"]:
        message = pgp(VARS, FROMADDRESS)
    # No signing of message
    else:
        message = send_normal(VARS)

    # Debug code
    #print(message.as_string())
    #sys.exit()

    try:
        #print(PORT)
        if PORT == 0 or PORT == 465:
            port465(VARS, message)
        elif PORT == 587:
            port587(VARS, message)
        elif PORT == 25:
            port25(VARS, message)
        else:
            error_exit(True, "Error: Wrong port specified. Use either 25 (local smtp server) or 465 or 587 (external SMTP server)")

    except smtplib.SMTPHeloError as e:
        print("Server did not reply. You may have Port 25 blocked on your host machine.")
        sys.exit(2)
    except smtplib.SMTPAuthenticationError as e:
        print("Incorrect username/password combination or, if you are using Google, you may need to lower the security settings (see the README.md for more information).")
        sys.exit(2)
    except smtplib.SMTPException as e:
        print(e)
        print("Authentication failed.")
        sys.exit(2)
    except Exception as error:
        import traceback
        traceback.print_exc()
        print(error)
        sys.exit(2)
