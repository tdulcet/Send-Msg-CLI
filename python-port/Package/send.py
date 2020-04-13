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

from mimetypes import guess_type

#from copy import deepcopy

def set_main_headers(VARS, message):
    # Set headers
    message["From"] = VARS["FROMEMAIL"]
    message["To"] = ", ".join(VARS["TOEMAILS"])
    #message["To"] = VARS["FROMEMAIL"] + ", " + ", ".join(VARS["TOEMAILS"])
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

def attachments2(attachments):
    message = MIMEMultipart()
    for path in attachments:
        with open(path, 'rb') as f1:
            part = MIMEApplication(
                    f1.read(),
                    name=op.basename(path))
        #encoders.encode_base64(part)
        part['Content-Disposition'] = 'attachment; filename="{}"'.format(op.basename(path))
        del part["MIME-Version"]
        message.attach(part)
    attachments = []
    for part in message.walk():
        print(part.get_content_type())
        if part.get_content_type() == "application/octet-stream":
            attachments.append(part)
            print(part)
        #sys.exit()
        #if part.is_attachment():
        #    print(part)
    return attachments
    sys.exit()

def attachments(message, attachments):
    '''

    If this ever fails, try this method: https://code.activestate.com/recipes/578150-sending-non-ascii-emails-from-python-3/
    '''
    import os
    #from email.header import Header
    for path in attachments:
        with open(path, 'rb') as f1:
            #part = MIMEApplication(
            part = MIMEApplication(
                    f1.read(),
                    name=f'{path}')
        part['Content-Disposition'] = f'attachment;' + f' filename="{path}"'
        del part["MIME-Version"]

# thanks to: https://stackoverflow.com/questions/10496902/pgp-signing-multipart-e-mails-with-python
def messageFromSignature(signature, content_type=None):
    message = EmailMessage()
    #message = Message()
    if content_type != None:
        message['Content-Type'] = content_type
    #signature.encode('ISO-8859-1')
    #encoders.encode_7or8bit(message)
    # ---- Another way to do it, this preserves the original ascii output to screen the bash has and also the "This is an S/MIME signed message" and the emojis as well, but won't preserve the emojis when printed out to screen.
    message.set_payload(signature)
    #message.set_payload(signature.encode('ascii', 'ignore'))
    # ------The below tries to send the message (AND MATCHES BASH), but can't due to the the ascii error
   # message.set_payload(signature)
    # ------The below sends the whole message with the attachment, but doesn't send the header
    #message.set_payload(signature, charset='utf-8') # IMPORTANT: must specify charset to utf-8 to get signed body messages that have emojis in them because later the sendmessage() function will try to convert the utf-8 character to ascii, but it will fail. But this implementation removes the string "This is an S/MIME signed message" in the header (not in the attachment that is sent).
    return message

def copyHeaders(m1, m2):
    """
    Replace the headers in m2 with the contents of m1, leaving m2's other headers intact.

    :type m1: email.message.Message
    :type m2: email.message.Message
    """
    first = True
    for i in m1.items():
        #if first:
        #    first = False
        #    continue
        if m2.get(i[0]):
            m2.replace_header(i[0], i[1])
        else:
            m2.add_header(i[0], i[1])

def send(VARS, FROMADDRESS, PORT=465):
#def send(VARS, PORT=25):
#def send(VARS, PORT=587):
    # openssl cms -sign -signer "$CLIENTCERT" -in "file.txt"

    # SMIME
    #print("CERT: " + VARS["CERT"])
    '''
    # SPARKY VERSION.... works for EVERYTHING but attachments...
    if VARS["CERT"]:
        import smime
        from OpenSSL import crypto
        message = {}
        message["From"] = VARS["FROMEMAIL"]
        message["To"] = ", ".join(VARS["TOEMAILS"])
        #message["To"] = VARS["FROMEMAIL"] + ", " + ", ".join(VARS["TOEMAILS"])
        if VARS["CCEMAILS"]:
            message["Cc"] = ", ".join(VARS["CCEMAILS"])
        if VARS["BCCEMAILS"]:
            message["Bcc"] = ", ".join(VARS["BCCEMAILS"])
        #message["Date"] = VARS["NOW"]
        message["Date"] = email.utils.formatdate(localtime=True)
        message["Subject"] = VARS["SUBJECT"]
        if VARS["PRIORITY"]:
            message["X-Priority"] = VARS["PRIORITY"]
        print(message)
    # ATTEMPTING THIS CURRENTLY TODO: https://stackoverflow.com/questions/32505722/signing-data-using-openssl-with-python
        import base64

        #print(crypto.sign(
        #sys.exit()

        # TODO -- create .pem file, take out linux openssl command

        # TODO (Conversion) convert two opens to Python's openssl library commands
        # read in certs
        with open("cert.key", "r") as key_file:
            key = key_file.read()
        with open("cert.crt", "r") as cert_file:
            cert = cert_file.read()
        #import pem
        #pkey, cert = pem.parse_file("cert.pem")
        #print(pkey)
        #print(cert)
        msg = MIMEText(VARS["MESSAGE"])
        # Wrap message with multipart/signed header
        msg2 = MIMEMultipart() # this makes a new boundary
        bound = msg2.get_boundary() # keep for later as we have to rewrite the header
        msg2.set_default_type('multipart/signed')
        copyHeaders(msg,msg2)
        del msg2['Content-Language'] # These don't apply to multipart/signed
        del msg2['Content-Transfer-Encoding']
        attachments(msg2, VARS["ATTACHMENTS"])
        set_main_headers(VARS, msg2)
        msg2.attach(MIMEText(VARS["MESSAGE"]))

        # "Create embedded pkcs7 signature)
        password = b'5C8Hvk2v1pKS'
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        signcert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        bio_in = crypto._new_mem_buf(msg.as_bytes())
        pkcs7 = crypto._lib.PKCS7_sign(signcert._x509, pkey._pkey, crypto._ffi.NULL, bio_in, 0x4)
        bio_out = crypto._new_mem_buf()
        crypto._lib.i2d_PKCS7_bio(bio_out, pkcs7)
        signed_data = crypto._bio_to_string(bio_out)

        sgn_part = MIMEApplication(signed_data, 'x-pkcs7-signature; name="smime.p7s"', _encoder=email.encoders.encode_base64)
        sgn_part.add_header('Content-Disposition', 'attachment; filename="smime.p7s"')
        msg2.attach(sgn_part)
        # Fix up Content-Type headers, as default class methods don't allow passing in protocol etc.
        msg2.replace_header('Content-Type', 'multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha1"; boundary="{}"'.format(bound))

        #cert = crypto.load_certificate(crypto.FILETYPE_PEM, "cert.pem")
        #print(pkey)
        #print(cert)
        #print(signed_data)


        #print(msg2.as_string())
        message = msg2
        #sys.exit()

        #cert = pem.parse_file("cert.pem")

        #data = "data"
        #import OpenSSL
        #sign = OpenSSL.crypto.sign(pkey, data, "sha256")
        #print(sign)

        #sys.exit()
        with open("cert.pem", "r") as key_file:
            key = key_file.read()
        password = "5C8Hvk2v1pKS"
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key, password.encode("utf-8"))

        if key.startswith('-----BEGIN '):
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key, password)
            sys.exit()
        else:
            pkey = crypto.load_pkcs12(key, password).get_privatekey()
        print(pkey)
        data = "data"
        sign = OpenSSL.crypto.sign(pkey, data, "sha256")
        print(sign)

        data_base64 = base64.b64encode(sign)
        print(data_base64)

        sys.exit()
        '''


     # This will have the verification symbol in all cases and matches the Bash output perfectly, but does not work with Yahoo Mail!
     # PIECE-DE-RESISTANCE -- Everything works...though its a bit sloppy
    if VARS["CERT"]:
        #cert_sig = subprocess.check_output("echo \""+VARS["MESSAGE"]+"\" | openssl cms -sign -signer "+VARS["CLIENTCERT"],shell=True)
        if not len(VARS["MESSAGE"]) > 0:
            print("No message to sign")
            sys.exit(1)
        #text = MIMEText(VARS["MESSAGE"], _charset="UTF-8")
        text = MIMEText(VARS["MESSAGE"])
        #set_main_headers(VARS, temp)
        del text["MIME-Version"]
        #print(str(text))
        #print(str(temp))

        if len(VARS["ATTACHMENTS"]) >= 0:
            #del text["Content-Transfer-Encoding"]
            #del text["Content-Type"]
            #for i in text.walk():
            #    text=i
            #sys.exit()
            temp = MIMEMultipart(boundary='"MULTPART-MIXED-BOUNDARY"')
            #temp = MIMEMultipart(boundary='\"----MULTPART-MIXED-BOUNDARY\"')
            del temp["MIME-Version"]
            temp.attach(text)
            #print(VARS["MESSAGE"])
            #sys.exit()
            attachments(temp, VARS["ATTACHMENTS"])
            #try:
                #cert_sig = subprocess.check_output("openssl cms -sign -in \"" +FILE THAT HAS str(temp)+"\" -signer \"" + VARS["CLIENTCERT"]+"\"",shell=True)
                #cert_sig = subprocess.check_output("openssl cms -sign -in 'Hello, world!' -signer \"" + VARS["CLIENTCERT"]+"\"",shell=True)
            #except Exception as error:
                #print(error)
            #    sys.exit()
            #sys.exit()
            cert_sig = subprocess.check_output("echo \""+str(temp)+"\" | openssl cms -sign -signer "+VARS["CLIENTCERT"],shell=True)
            #cert_sig = subprocess.check_output("echo \""+temp.as_string()+"\" | openssl cms -sign -signer "+VARS["CLIENTCERT"],shell=True)
            #temp.set_payload(text)
            #temp.attach(text)
        else: # TODO -- delete
            cert_sig = subprocess.check_output("echo \""+str(text)+"\" | openssl cms -sign -signer "+VARS["CLIENTCERT"],shell=True)
        #cert_sig = subprocess.check_output("echo \""+VARS["MESSAGE"]+"\" | openssl cms -sign -signer "+VARS["CLIENTCERT"],shell=True)
        msg = email.message_from_bytes(cert_sig)
        #msg.set_payload(attachments2(VARS["ATTACHMENTS"]))
        #msg.attach(email.message_from_string(attachments2(VARS["ATTACHMENTS"])))

        #attachments(msg, VARS["ATTACHMENTS"])
        #msg.attach(email.message_from_string(temp.as_string()))
        set_main_headers(VARS, msg)
        #print(msg.as_string())
        #print(msg.keys())
        message = msg
        '''
        for part in message.walk():
            print(part)
            import time
            time.sleep(2)
        sys.exit()
        '''

        #for i in message.walk():
        #    print(i.get_content_maintype())
        #sys.exit()
        # stop here

    # PGP
    elif VARS["PASSPHRASE"]:
        if not len(VARS["MESSAGE"]) > 0:
            print("No message to sign")
            sys.exit(1)
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

    # TODO -- try this https://stackoverflow.com/questions/10496902/pgp-signing-multipart-e-mails-with-python
#    gpg = gnupg.GPG()

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
