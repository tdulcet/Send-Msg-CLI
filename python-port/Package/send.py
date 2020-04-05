import email, smtplib, ssl, socket, sys
import os.path as op
import gnupg # Signs email with given certificate |  TODO -- make only for Windows users? # 0

from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

gpg_passphrase = "5512" # TODO  # 1

#send(VARS["SUBJECT"], VARS["MESSAGE"], VARS["USERNAME"], VARS["PASSWORD"], VARS["TOEMAILS"], VARS["CCEMAILS"], VARS["BCCEMAILS"], VARS["NOW"], VARS["ATTACHMENTS"], VARS["PRIORITY"], VARS["SMTP"], VARS["VERBOSE"], VARS["SMIME"], VARS["PASSPHRASE"], VARS["DRYRUN"])
#def send(SUBJECT=None, MESSAGE=None, USERNAME=None, PASSWORD=None, TOEMAILS=None, CC=None, BCC=None, DATE=None, ATTACHMENTS=None, PRIORITY=None, SMTP=None, VERBOSE=None, SMIME=None, GPG=None, DRYRUN=False, PORT=465):

def send(VARS, PORT=465):
    #print(SMIME)
    h = email.header.Header()
    # Create a multipart message and set headers
    # TODO -- if SMIME:
      #        do SMIME header     else: .... do mime header
    #message = MIMEMultipart("signed")
    message = MIMEMultipart()

    # Send message normally
    #if VARS["CERT"] == '' and VARS["PASSPHRASE"] == '':
    message["From"] = VARS["USERNAME"]
    message["To"] = ", ".join(VARS["TOEMAILS"])
    message["Bcc"] = ""
    message["Cc"] = ", ".join(VARS["CCEMAILS"])
    message["Date"] = VARS["NOW"]
    message["Subject"] = VARS["SUBJECT"]
    message["X-Priority"] = VARS["PRIORITY"]

    # Add body.
    message.attach(MIMEText(VARS["MESSAGE"], "plain"))
    #print(message.as_string()) # BCC here keeps senders annoymous as we don't explicitly declare a header

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
    #context = ssl.create_default_context() if VARS["CERT"] == '' else ssl._create_unverified_context(certfile="./"+VARS["CERT"], keyfile="./"+VARS["CLIENTCERT"])
    #context = ssl.create_default_context(cafile="./"+VARS["CERT"], capath=VARS["CLIENTCERT"])
    context = ssl._create_unverified_context()
    #context = ssl.create_default_context()

    #context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    #context.load_cert_chain(VARS["CLIENTCERT"], keyfile=VARS["CERT"])
    #context.load_cert_chain(VARS["CERT"], keyfile=VARS["CLIENTCERT"])
   # context.load_cert_chain("./"+VARS["CERT"], keyfile="./"+VARS["CLIENTCERT"])

    try:
        if not VARS["DRYRUN"]:
            #with smtplib.SMTP_SSL(VARS["SMTP"], PORT, context=context) as server:
            #with smtplib.SMTP(VARS["SMTP"], PORT) as server:
            with smtplib.SMTP(VARS["SMTP"], 587) as server: # https://www.mailgun.com/blog/which-smtp-port-understanding-ports-25-465-587/
            #with smtplib.SMTP(VARS["SMTP"], PORT) as server:
                # "Often the private key is stored in the same file as the certificate; in this case, only the certfile parameter need be passed." -- SSL wrapper for wrap_socket() documentation. Also applies here?

                server.starttls(certfile=VARS["CLIENTCERT"])
                #server.wrap_socket(certfile=VARS["CLIENTCERT"], context=context)
                #server.starttls(keyfile=VARS["CERT"],certfile=VARS["CLIENTCERT"])
                #server.starttls()
                #server.ehlo()
                #server.starttls(certfile=VARS["CERT"],)
                #server.ehlo()
                if VARS["VERBOSE"]:
                    server.set_debuglevel(2)
                #server.login(VARS["USERNAME"], VARS["PASSWORD"], context)
                server.login(VARS["USERNAME"], VARS["PASSWORD"])
                #server.sendmail(VARS["USERNAME"], [VARS["TOEMAILS"]] + VARS["BCCEMAILS"], message.as_string()) # TODO BCC added this way is SUPPOSED to keep recipients annoymous as we don't explicitly declare a header, but it doesn't (double check)
                print(message.as_string())
                server.sendmail(VARS["USERNAME"], ", ".join(VARS["TOEMAILS"]), message.as_string()) # TODO BCC added this way is SUPPOSED to keep recipients annoymous as we don't explicitly declare a header, but it doesn't (double check). Also, we are getting a BCC header when none exists...
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

    #message.attach(MIMEText(SMIME, "multipart/signed"))

    #message["Subject"].append(SMIME)
    #message."Content-Type: multipart/mixed; boundary=\"MULTIPART-MIXED-BOUNDARY    \"\n\n--MULTIPART-MIXED-BOUNDARY\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\    n\n$2\n$(for i in "${@:3}"; do echo "--MULTIPART-MIXED-BOUNDARY\nContent-Type: $(file --mime-type "$i" | se    d -n 's/^.\+: //p')\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename*=utf-8''$    (curl -Gs -w "%{url_effective}\\n" --data-urlencode "$(basename "$i")" "" | sed -n 's/\/?//p')\n\n$(base64     "$i")\n"; done)--MULTIPART-MIXED-BOUNDARY--"
    #message="Content-Type: multipart/mixed; boundary=\"MULTIPART-MIXED-BOUNDARY    \"\n\n--MULTIPART-MIXED-BOUNDARY\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\    n\n$2\n$(for i in "${@:3}"; do echo "--MULTIPART-MIXED-BOUNDARY\nContent-Type: $(file --mime-type "$i" | se    d -n 's/^.\+: //p')\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename*=utf-8''$    (curl -Gs -w "%{url_effective}\\n" --data-urlencode "$(basename "$i")" "" | sed -n 's/\/?//p')\n\n$(base64     "$i")\n"; done)--MULTIPART-MIXED-BOUNDARY--"
    #message.add_header

