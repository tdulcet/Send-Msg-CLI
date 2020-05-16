import email
import smtplib
import ssl
import sys
import subprocess
import atexit
import os
import time
import locale
import socket

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import EmailMessage
from email.mime.application import MIMEApplication

'''Copyright © Daniel Connelly

   The purpose of this file is to fill a MIME object, possibly with sub MIME objects, with the necessary
   values/attachments/keys to send the message requested by the user.
'''


def error_exit(condition, err):
    '''print an error and exit when one occurs'''
    if condition:
        sys.stderr.write(err)
        sys.exit(1)


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
        part['Content-Disposition'] = f'attachment;' + \
            f' filename='+os.path.basename(path)
        del part["MIME-Version"]
        message.attach(part)


def messageFromSignature(signature, content_type=None):
    '''Returns the pgp message signature as a payload of the message'''
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
    if VARS["LANGUAGE"]:
        text['Content-Language'] = locale.getdefaultlocale()[0].replace('_', '-')
    del text["MIME-Version"]

    temp_msg = MIMEMultipart()
    del temp_msg["MIME-Version"]
    temp_msg.attach(text)
    attachments(temp_msg, VARS["ATTACHMENTS"])

    with open("message", "w") as f1:
        f1.write(str(temp_msg))
    atexit.register(lambda x: os.remove(x), "message")

    platform = sys.platform
    if sys.platform == 'darwin':
        p = subprocess.Popen("openssl smime -sign -in message -signer \"" +
                             VARS["CLIENTCERT"] + "\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        p = subprocess.Popen("openssl cms -sign -in message -signer \"" +
                             VARS["CLIENTCERT"] + "\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    cert_sig, stderr = [x.decode().replace("\r\n", "\n")
                        for x in p.communicate()]
    message = email.message_from_bytes(bytes(cert_sig, "utf-8"))
    set_main_headers(VARS, message)
    return message


def pgp(VARS):
    '''Signs message + attachments with PGP key'''
    if not len(VARS["MESSAGE"]) > 0:
        print("No message to sign")
        sys.exit(1)

    message = MIMEMultipart(
        _subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
    if VARS["LANGUAGE"]:
        message['Content-Language'] = locale.getdefaultlocale()[0].replace('_', '-')

    basemsg = MIMEText(VARS["MESSAGE"], _charset="utf-8")
    del basemsg["MIME-Version"]
    message.attach(basemsg)
    attachments(message, VARS["ATTACHMENTS"])

    with open("message", "w") as f1:
        f1.write(str(message))
    atexit.register(lambda x: os.remove(x), "message")

    p = subprocess.Popen("gpg --pinentry-mode loopback --batch -o - -ab -u \"" +
                         VARS["FROMADDRESS"]+"\" --passphrase-fd 0 message", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pgp_sig = p.communicate(bytes(VARS["PASSPHRASE"], "utf-8"))[0].decode()
    signmsg = messageFromSignature(
        pgp_sig, 'application/pgp-signature; name="signature.asc"')
    signmsg['Content-Disposition'] = 'attachment; filename="signature.asc"'
    set_main_headers(VARS, message)
    message.attach(signmsg)
    return message


def send_normal(VARS):
    '''Sends (does not sign) a message'''
    mime_text = MIMEText(VARS["MESSAGE"], "plain")
    if VARS["LANGUAGE"]:
        mime_text['Content-Language'] = locale.getdefaultlocale()[0].replace('_', '-')

    del mime_text["MIME-Version"]

    # Attachments require a multipart object; else, just a mimetext object.
    if VARS["ATTACHMENTS"]:
        message = MIMEMultipart()
        message.attach(mime_text)
        attachments(message, VARS["ATTACHMENTS"])
    else:
        message = mime_text
    set_main_headers(VARS, message)
    return message


def port465(VARS, message, PORT=465):
    '''Log in to server using secure context from the onset and send email. This uses SSL/TLS.'''
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(VARS["SMTP"], PORT, context=context, timeout=10) as server:
        if VARS["VERBOSE"]:
            server.set_debuglevel(2)
        server.login(VARS["USERNAME"], VARS["PASSWORD"])
        # send_message() annoymizes BCC, rather than sendmail().
        server.send_message(message)
        print("Message sent\n")


def port587(VARS, message, PORT=587):
    '''Create an unsecured connection, then secure it, and then send email. This uses startTLS.'''
    context = ssl.create_default_context()
    with smtplib.SMTP(VARS["SMTP"], PORT, timeout=10) as server:
        server.starttls(context=context)
        if VARS["VERBOSE"]:
            server.set_debuglevel(2)
        server.login(VARS["USERNAME"], VARS["PASSWORD"])
        # send_message() annoymizes BCC, rather than sendmail().
        server.send_message(message)
        print("Message sent\n")


def port25(VARS, message, PORT=25):
    '''Use a local SMTP server connection to send email'''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, timeout=10) as sock:
        # testing connection as computer may not block port 25, but ISP/Cloud provider may.
        if sock.connect_ex(('aspmx.l.google.com', 25)) != 0:
            error_exit(True, "Warning: Could not reach Google's mail server on port 25. Port 25 seems to be blocked by your network. You will need to provide an external SMTP server in order to send e-mails.\n")

    with smtplib.SMTP(VARS["SMTP"], PORT) as server:
        if VARS["VERBOSE"]:
            server.set_debuglevel(2)
        # send_message() annoymizes BCC, rather than sendmail().
        server.send_message(message)
        print("Message MAY have been sent; this program can only check if port 25 is blocked.\n")


def sendEmail(VARS, PORT=0):
    '''This function compiles our (optionally signed) message and calls the correct send function according to what port is entered.'''
    if VARS["DRYRUN"]:
        return
    if VARS["TIME"]:
        time.sleep(int(VARS["TIME"]))
    # S/MIME
    if VARS["CERT"]:
        message = smime(VARS)
    # PGP
    elif VARS["PASSPHRASE"]:
        message = pgp(VARS)
    # No signing of message
    else:
        message = send_normal(VARS)

    # Debug code
    # print(message.as_string())
    # sys.exit()

    try:
        if VARS["TLS"] or PORT == 465:
            port465(VARS, message, PORT)
        elif VARS["STARTTLS"] or PORT == 587:
            port587(VARS, message, PORT)
        elif PORT == 0 or PORT == 25:
            port25(VARS, message, PORT)
        else:
            error_exit(
                True, "Non-standard port chosen, but --tls or --starttls flags were not selected. Please add the correct protocol/flag and try again.")

    except socket.timeout:
        error_exit(True, "Connection timed out when trying to connect. Please verify the server is up or you entered the correct port number for the SMTP server.")
    except smtplib.SMTPHeloError as e:
        print("Server did not reply. You may have Port 25 blocked on your host machine.")
        sys.exit(2)
    except smtplib.SMTPAuthenticationError as e:
        print(e)
        print("Incorrect username/password combination or, if you are using Google, you may need to lower the security settings or login from this computer (see the README.md for more information).")
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
