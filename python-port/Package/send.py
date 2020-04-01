import email, smtplib, ssl, socket, sys
import os.path as op
import gnupg # Signs email with given certificate |  TODO -- make only for Windows users? # 0

from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

gpg_passphrase = "5C8Hvk2v1pKS" # TODO  # 1

def send(SUBJECT=None, MESSAGE=None, USERNAME=None, PASSWORD=None, TOEMAILS=None, CC=None, BCC=None, DATE=None, ATTACHMENTS=None, PRIORITY=None, SMTP=None, VERBOSE=None, PORT=465):

    # Create a multipart message and set headers
    message = MIMEMultipart()
    message["From"] = USERNAME
    message["To"] = ", ".join(TOEMAILS)
    message["Cc"] = ", ".join(CC)
    message["Date"] = DATE
    message["Subject"] = SUBJECT
    message["X-Priority"] = PRIORITY

    # Add body.
#    basemsg = MIMEText(MESSAGE, "plain")
    message.attach(MIMEText(MESSAGE, "plain"))

    # TODO -- try this https://stackoverflow.com/questions/10496902/pgp-signing-multipart-e-mails-with-python
#    gpg = gnupg.GPG()
    # basetext =...
#    signature = str(gpg.sign(


    # Add attachments - https://stackoverflow.com/questions/3362600/how-to-send-email-attachments
    for path in ATTACHMENTS:
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
        with smtplib.SMTP_SSL(SMTP, PORT, context=context) as server:
        #with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            if VERBOSE:
                server.set_debuglevel(2)
            server.login(USERNAME, PASSWORD)
            server.sendmail(USERNAME, [TOEMAILS] + BCC, message.as_string()) # BCC here keeps senders annoymous as we don't explicitly declare a header
    except smtplib.SMTPHeloError as e:
        print("Server did not reply. You may have Port 25 blocked on your host machine.")
        sys.exit(2)
    except smtplib.SMTPAuthenticationError as e:
        print("Incorrect username/password combination or, if you are using Google, you may need to lower the security settings (see the README.md for more information).")
        sys.exit(2)
    except smtplib.SMTPException as e:
        print("Authentication failed.")
        sys.exit(2)
    except Exception as error:
        import traceback
        traceback.print_exc()
        print(error)
        sys.exit(2)
