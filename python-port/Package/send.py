import email, smtplib, ssl, socket, sys
import os.path as op
import subprocess
import gnupg # Signs email with given certificate |  TODO -- make only for Windows users? # 0

from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.message import MIMEMessage
from email.message import EmailMessage
from email.mime.application import MIMEApplication
from email.message import Message

#from copy import deepcopy

#gpg_passphrase = "5512" # TODO  # 1

def set_main_headers(VARS, message):
    # Set headers
    message["From"] = VARS["FROMEMAIL"]
    message["To"] = ", ".join(VARS["TOEMAILS"])
    if VARS["CCEMAILS"]:
        message["Cc"] = ", ".join(VARS["CCEMAILS"])
    if VARS["BCCEMAILS"]:
        message["Bcc"] = ", ".join(VARS["BCCEMAILS"])
    #message["Date"] = VARS["NOW"]
    message["Date"] = email.utils.formatdate(localtime=True)
    message["Subject"] = VARS["SUBJECT"]
    if VARS["PRIORITY"]:
        message["X-Priority"] = VARS["PRIORITY"]
    return message
    #message.__delitem__('Bcc') # remove Bcc area

def attachments(message, attachments):
    for path in attachments:
        with open(path, 'rb') as f1:
            part = MIMEApplication(
                    f1.read(),
                    name=op.basename(path))
        #encoders.encode_base64(part)
        part['Content-Disposition'] = 'attachment; filename="{}"'.format(op.basename(path))
        del part["MIME-Version"]
        message.attach(part)

# thanks to: https://stackoverflow.com/questions/10496902/pgp-signing-multipart-e-mails-with-python
def messageFromSignature(signature, content_type=None):
    message = EmailMessage()
    #message = Message()
    if content_type != None:
        message['Content-Type'] = content_type
    #signature.encode('ISO-8859-1')
    encoders.encode_7or8bit(message)
    message.set_payload(signature, charset='utf-8') # IMPORTANT: must specify charset to utf-8 to get signed body messages that have emojis in them (TODO: WHY?). But it does remove the string "This is an S/MIME signed message" in the header (not in the attachment).
    return message

def send(VARS, FROMADDRESS, PORT=465):
#def send(VARS, PORT=25):
#def send(VARS, PORT=587):
    # openssl cms -sign -signer "$CLIENTCERT" -in "file.txt"

    # SMIME
    #print("CERT: " + VARS["CERT"])
    if VARS["CERT"]:
        cert_sig = subprocess.check_output("echo \""+VARS["MESSAGE"]+"\" | openssl cms -sign -signer "+VARS["CLIENTCERT"],shell=True).decode().strip("\n")
        # TODO -- add check for VARS["MESSAGE"] being None, here or elsewhere
        basemsg = MIMEText(VARS["MESSAGE"])
        del basemsg["MIME-Version"]
        signmsg = messageFromSignature(cert_sig, 'application/pkcs7-signature; name="smime.p7s"')
        signmsg['Content-Disposition'] = 'attachment; filename="smime.p7s"'
        del signmsg["MIME-Version"]
        message = MIMEMultipart(_subtype="signed", micalg="sha-256", protocol="application/pkcs7-signature")
        attachments(message, VARS["ATTACHMENTS"])
        set_main_headers(VARS, message)
        message.attach(basemsg)
        message.attach(signmsg)

    # PGP
    elif VARS["PASSPHRASE"]:
        pgp_sig = subprocess.check_output("echo \""+VARS["PASSPHRASE"]+"\" | gpg --pinentry-mode loopback --batch -o - -ab -u \""+FROMADDRESS+"\" --passphrase-fd 0", shell=True).decode().strip("\n")
        basemsg = MIMEText(VARS["MESSAGE"], _charset="utf-8")
        del basemsg["MIME-Version"]
        signmsg = messageFromSignature(pgp_sig, 'application/pgp-signature; name="signature.asc"')
        signmsg['Content-Disposition'] = 'attachment; filename="signature.asc"'
        message = MIMEMultipart(_subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
        set_main_headers(VARS, message)
        attachments(message, VARS["ATTACHMENTS"])
        message.attach(basemsg)
        message.attach(signmsg)

    # No signing of message
    else:
        # Add attachments; thanks to Oli at https://stackoverflow.com/questions/3362600/how-to-send-email-attachments
        mime_text = MIMEText(VARS["MESSAGE"], "plain")
        del mime_text["MIME-Version"]
        if VARS["ATTACHMENTS"]:
            message = MIMEMultipart()
            message.attach(mime_text)

            set_main_headers(VARS, message)
            for path in VARS["ATTACHMENTS"]:
                with open(path, 'rb') as f1:
                    part = MIMEApplication(
                            f1.read(),
                            name=op.basename(path))
                encoders.encode_base64(part)
                part['Content-Disposition'] = 'attachment; filename="{}"'.format(op.basename(path))
                message.attach(part)

        # Sending a message with an attachment requires Mutlipart()
        if not VARS["ATTACHMENTS"]:
            message = mime_text
            set_main_headers(VARS, message)

    # TODO -- try this https://stackoverflow.com/questions/10496902/pgp-signing-multipart-e-mails-with-python
#    gpg = gnupg.GPG()

    #print(message.as_string())
    # DEBUG-CODE: iterate through the message header/content. OR print message as string
    print(message.as_string())
    #for part in message.walk():
        #print("PART")
        #print(part)

    # Log in to server using secure context and send email. Port 465 is for ssl (587 for starttls)
    context = ssl.create_default_context()

    try:
        if not VARS["DRYRUN"]:
            with smtplib.SMTP_SSL(VARS["SMTP"], PORT, context=context) as server:
                if VARS["VERBOSE"]:
                    server.set_debuglevel(2)
                server.login(VARS["USERNAME"], VARS["PASSWORD"])
                server.send_message(message) # send_message() annoymizes BCC, rather than sendmail().
                #server.sendmail(VARS["FROMEMAIL"], VARS["TOEMAILS"], message.as_string()) # send_message() annoymizes BCC, rather than sendmail().
                #print("Message sent")
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
