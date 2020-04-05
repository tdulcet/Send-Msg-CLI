import email, smtplib, ssl, socket, sys
import os.path as op
import gnupg # Signs email with given certificate |  TODO -- make only for Windows users? # 0

from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.message import MIMEMessage
from email.message import Message

from copy import deepcopy

gpg_passphrase = "5512" # TODO  # 1

def pgpMessageFromSignature(signature):
    message = Message()
    message['Content-Type'] = 'application/pgp-signature; name="signature.asc"'
    message['Content-Description'] = 'OpenPGP digital signature'
    message.set_payload(signature)
    return message

#def send(VARS, PORT=465):
def send(VARS, PORT=587): # Reason for port: https://www.mailgun.com/blog/which-smtp-port-understanding-ports-25-465-587/
    # Create a multipart message and set headers
    #message = MIMEMultipart("application/pgp-signature")
    #message = MIMEMultipart()
    #message = MIMEMessage()

    # PGP
    if VARS["PGP"]:
        #msg2 = MIMEMultipart()
        #message.attach(MIMEText(VARS["PGP"], "multipart/signed"))
        pass
    basemsg = MIMEText(VARS["MESSAGE"])
    signmsg = pgpMessageFromSignature(MIMEVARS["PGP"])
    message = MIMEMultipart(_subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
    message.attach(basemsg)
    message.attach(signmsg)

    #for part in message.walk():
    #    print(part)

    # Send message normally
    #if VARS["CERT"] == '' and VARS["PASSPHRASE"] == '':
    message["From"] = VARS["USERNAME"]
    message["To"] = ", ".join(VARS["TOEMAILS"])
    message["Bcc"] = ""
    message["Cc"] = ", ".join(VARS["CCEMAILS"])
    message["Date"] = VARS["NOW"]
    message["Subject"] = VARS["SUBJECT"]
    message["X-Priority"] = VARS["PRIORITY"]

    #message.set_payload(
    # Add body.

    #message.attach(MIMEText(VARS["MESSAGE"], "plain"))
    #print("SMIME: " + VARS["SMIME"])
    if VARS["SMIME"]:
        print("YES VARS IS HERE")
        sys.exit()
    elif VARS["PGP"]:
        #msg2 = MIMEMultipart()
        #message.attach(MIMEText(VARS["PGP"], "multipart/signed"))
        pass

    # iterate through the message
    for part in message.walk():
        print(part)
    #sys.exit()

    #sgn
    #message.attach
   # print(message.as_string()) # BCC here keeps senders annoymous as we don't explicitly declare a header

    # TODO -- try this https://stackoverflow.com/questions/10496902/pgp-signing-multipart-e-mails-with-python
#    gpg = gnupg.GPG()
    # basetext =..
#    signature = str(gpg.sign(

    # Add attachments - https://stackoverflow.com/questions/3362600/how-to-send-email-attachments
    for path in VARS["ATTACHMENTS"]:
        part = MIMEBase('application', "octet-stream")
        with open(path, 'rb') as f1:
            part.set_payload(f1.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition',
                        'attachment; filename="{}"'.format(op.basename(path)))
        message.attach(part)

    # Log in to server using secure context and send email. Port 465 is for ssl (587 for starttls)
    context = ssl.create_default_context()

    try:
        if not VARS["DRYRUN"]:
            with smtplib.SMTP_SSL(VARS["SMTP"], 465, context=context) as server:
            #with smtplib.SMTP(VARS["SMTP"], PORT) as server:
                # "Often the private key is stored in the same file as the certificate; in this case, only the certfile parameter need be passed." -- SSL wrapper for wrap_socket() documentation. Also applies here?
                if VARS["VERBOSE"]:
                    server.set_debuglevel(2)
                server.login(VARS["USERNAME"], VARS["PASSWORD"])
                #server.sendmail(VARS["USERNAME"], [VARS["TOEMAILS"]] + VARS["BCCEMAILS"], message.as_string()) # TODO BCC added this way is SUPPOSED to keep recipients annoymous as we don't explicitly declare a header, but it doesn't (double check)
                #print(message.as_string())
                server.sendmail(VARS["USERNAME"], ", ".join(VARS["TOEMAILS"]), message.as_string()) # TODO BCC added this way is SUPPOSED to keep recipients annoymous as we don't explicitly declare a header, but it doesn't (double check). Also, we are getting a BCC header when none exists...
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
