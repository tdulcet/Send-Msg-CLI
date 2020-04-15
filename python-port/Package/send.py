import email, smtplib, ssl
import sys
import subprocess

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.message import MIMEMessage
from email.message import EmailMessage
from email.mime.application import MIMEApplication

"""The purpose of this file is to fill a MIME object message with sub MIME objects and the necessary
   values/attachments/keys to send the message requested by the user.
"""

def set_main_headers(VARS, message):
    # Set headers
    message["From"] = VARS["FROMEMAIL"]
    message["To"] = ", ".join(VARS["TOEMAILS"])
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

# thanks to: https://stackoverflow.com/questions/10496902/pgp-signing-multipart-e-mails-with-python
def messageFromSignature(signature, content_type=None):
    message = EmailMessage()
    if content_type != None:
        message['Content-Type'] = content_type
    message.set_payload(signature)
    return message

def smime(VARS):
    if not len(VARS["MESSAGE"]) > 0:
        print("No message to sign")
        sys.exit(1)

    text = MIMEText(VARS["MESSAGE"])
    del text["MIME-Version"]

    temp = MIMEMultipart()
    del temp["MIME-Version"]
    temp.attach(text)
    attachments(temp, VARS["ATTACHMENTS"])

    with open("message", "w") as f1:
        f1.write(str(temp))
    cert_sig = subprocess.check_output("openssl cms -sign -in message -signer "+VARS["CLIENTCERT"],shell=True)
    subprocess.run("rm message", shell=True)

    msg = email.message_from_bytes(cert_sig)
    set_main_headers(VARS, msg)
    return msg

def pgp(VARS, FROMADDRESS):
    if not len(VARS["MESSAGE"]) > 0:
        print("No message to sign")
        sys.exit(1)

    with open("message", "w") as f1:
        f1.write(VARS["MESSAGE"])
    pgp_sig = subprocess.check_output("gpg --pinentry-mode loopback --batch -o - -ab -u \""+FROMADDRESS+"\" --passphrase \""+VARS["PASSPHRASE"]+"\" message", shell=True).decode().strip("\n")
    subprocess.run("rm message", shell=True)
    basemsg = MIMEText(VARS["MESSAGE"], _charset="utf-8")
    del basemsg["MIME-Version"]
    signmsg = messageFromSignature(pgp_sig, 'application/pgp-signature; name="signature.asc"')
    signmsg['Content-Disposition'] = 'attachment; filename="signature.asc"'
    message = MIMEMultipart(_subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
    set_main_headers(VARS, message)
    attachments(message, VARS["ATTACHMENTS"])
    message.attach(basemsg)
    message.attach(signmsg)
    return message

def send_normal(VARS):
    # Sending a message with an attachment requires Mutlipart()
    mime_text = MIMEText(VARS["MESSAGE"], "plain")
    del mime_text["MIME-Version"]
    if VARS["ATTACHMENTS"]:
        message = MIMEMultipart()
        message.attach(mime_text)

        set_main_headers(VARS, message)
        attachments(message, VARS["ATTACHMENTS"])

    # Otherwise, just a regular text message is sufficient
    if not VARS["ATTACHMENTS"]:
        message = mime_text
        set_main_headers(VARS, message)
    return message

# TODO -- handle local SMTP server.
def send(VARS, FROMADDRESS, PORT=465):
#def send(VARS, PORT=25):
#def send(VARS, PORT=587):
    '''This function compiles our (optionally signed) message'''
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

    # Log in to server using secure context and send email. Port 465 is for ssl (587 for starttls)
    context = ssl.create_default_context()

    try:
        if not VARS["DRYRUN"]:
            with smtplib.SMTP_SSL(VARS["SMTP"], PORT, context=context) as server:
                if VARS["VERBOSE"]:
                    server.set_debuglevel(2)
                server.login(VARS["USERNAME"], VARS["PASSWORD"])
                server.send_message(message) # send_message() annoymizes BCC, rather than sendmail().
                print("Message sent")
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
