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

# thanks to: https://stackoverflow.com/questions/10496902/pgp-signing-multipart-e-mails-with-python
def messageFromSignature(signature, content_type=None):
    message = EmailMessage()
    #message.set_content(fmt.format(to_, from_, subject, msg))
    #message = Message()
    if content_type != None:
        message['Content-Type'] = content_type
    #signature.encode('ISO-8859-1')
    encoders.encode_7or8bit(message)
    message.set_payload(signature)
    return message

def send(VARS, FROMADDRESS, PORT=465):
#def send(VARS, PORT=25):
#def send(VARS, PORT=587):
    # openssl cms -sign -signer "$CLIENTCERT" -in "file.txt"

    # SMIME
    print("CERT: " + VARS["CERT"])
    if VARS["CERT"]:
        cert_sig = subprocess.check_output("echo \""+VARS["MESSAGE"]+"\" | openssl cms -sign -signer "+VARS["CLIENTCERT"],shell=True).decode().strip("\n")
        # TODO -- add check for VARS["MESSAGE"] being None, here or elsewhere
        #message = MIMEMessage(MIMEText(_text=cert_sig, _charset="utf-8"))
        #message['Content-Disposition'] = 'attachment; filename="smime.p7s"'
        #print(message)
        #sys.exit()
        #message = MIMEMessage(MIMEText(cert_sig,"plain"))
        #signmsg = messageFromSignature(cert_sig)
        #signmsg = messageFromSignature(cert_sig, 'text/plain')
        #signmsg = messageFromSignature(cert_sig) # 'application/pkcs7-signature; name="smime.p7s"')
        #print(cert_sig)
        #sys.exit()
        #message = MIMEMultipart(_subtype="mixed")
        #message = MIMEMultipart(_subtype="signed", micalg="sha-256", protocol="application/pkcs7-signature")
        #message = MIMEMultipart(_subtype="signed", micalg="sha-256") #protocol="application/pkcs7-signature")
        #encoders.encode_7or8bit(message)
        #message.attach(basemsg)
        #message.attach(MIMEMessage(MIMEText(_text=cert_sig), "signed"))
        mime_signed = MIMEText(_text=cert_sig, _subtype="plain")
        #del mime_signed["MIME-Version"]
        del mime_signed["MIME-Version"]
        print(mime_signed.keys())

        #print(mime_signed.replace_header(_name="MIME-Version", _value=""))
        message = MIMEMessage(mime_signed)
        del message["MIME-Version"]
        #message.encode()
        #message = MIMEMessage(MIMEText(_text=cert_sig), "plain")

    # PGP
    elif VARS["PASSPHRASE"]:
        pgp_sig = subprocess.check_output("echo \""+VARS["PASSPHRASE"]+"\" | gpg --pinentry-mode loopback --batch -o - -ab -u \""+FROMADDRESS+"\" --passphrase-fd 0", shell=True).decode().strip("\n")
        basemsg = MIMEText(VARS["MESSAGE"])
        signmsg = messageFromSignature(pgp_sig, 'application/pgp-signature; name="signature.asc"')
        signmsg['Content-Disposition'] = 'attachment; filename="signature.asc"'
        message = MIMEMultipart(_subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
        message.attach(basemsg)
        message.attach(signmsg)

    # No signing of message
    else:
        # Add attachments; thanks to: https://stackoverflow.com/questions/3362600/how-to-send-email-attachments
        if VARS["ATTACHMENTS"]:
            message = MIMEMultipart()
            mime_text = MIMEText(VARS["MESSAGE"], "plain")
            del mime_text["MIME-Version"]
            message.attach(mime_text)

            set_main_headers(VARS, message)


            part = None
            for path in VARS["ATTACHMENTS"]:
                print("HERE")
                #part = Message()
                #message = MIMEBase()
                #part = MIMEBase('application', "octet-stream")
                with open(path, 'rb') as f1:
                    #part.set_payload(f1.read())
                    part = MIMEApplication(
                            f1.read(),
                            name=op.basename(path))
               #     message.header.append(f1.read())
                encoders.encode_base64(part)

                part['Content-Disposition'] = 'attachment; filename="{}"'.format(op.basename(path))
                #part.add_header('Content-Disposition',
                #                'attachment; filename="{}"'.format(op.basename(path)))
                message.attach(part)
            #print(message.as_string())
        #message = MIMEBase('application', "octet-stream", __text=message.as_string() + part.as_string())
        # Regular message, no attachments
        #mime_text = MIMEText(VARS["MESSAGE"], "plain")
        #del mime_text["MIME-Version"]
        if not VARS["ATTACHMENTS"]:
            message = MIMEText(VARS["MESSAGE"],"plain")

        # Sending a message with an attachment requires Mutlipart()
        else:
            pass
            #message = MIMEMultipart()
            #message.attach(mime_text)

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
