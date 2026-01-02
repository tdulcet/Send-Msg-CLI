import locale
import mimetypes
import os
import smtplib
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import localtime

import pgp
import smime

"""Copyright © Daniel Connelly and Teal Dulcet

   The purpose of this file is to fill a MIME object, possibly with sub MIME objects, with the necessary
   values/attachments/keys to send the message requested by the user.
"""

context = ssl.create_default_context()


def set_main_headers(args, message):
    """Set common headers in every email."""
    COMMASPACE = ", "
    message["User-Agent"] = "Send Msg CLI/SendPy"
    message["From"] = args.fromemail
    message["To"] = "undisclosed-recipients:;" if not args.toemails and not args.ccemails else COMMASPACE.join(args.toemails)
    if args.ccemails:
        message["Cc"] = COMMASPACE.join(args.ccemails)
    if args.bccemails:
        message["Bcc"] = COMMASPACE.join(args.bccemails)
    message["Subject"] = args.subject
    message["Date"] = datetime.fromtimestamp(int(datetime.now().timestamp()) // 60 * 60, timezone.utc) if args.utc else localtime()
    if args.priority:
        message["X-Priority"] = args.priority
    if args.mdn:
        message["Disposition-Notification-To"] = args.fromemail
    return message


def attachments(message, aattachments):
    """Create a MIMEApplication method with our attachment as a payload and then attach it to our main message."""
    for file in aattachments:
        ctype, encoding = mimetypes.guess_type(file)  # guess_file_type(file)
        if ctype is None or encoding is not None:
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        with open(file, "rb") as f:
            message.add_attachment(f.read(), maintype=maintype, subtype=subtype, filename=os.path.basename(file))


def send_normal(args, lang):
    """Sends (does not sign) a message."""
    msg = EmailMessage()
    msg.set_content(args.message, cte="quoted-printable")
    if args.language and lang:
        msg["Content-Language"] = lang.replace("_", "-")

    # Attachments require a multipart object; else, just a mimetext object.
    if args.attachments:
        attachments(msg, args.attachments)

    set_main_headers(args, msg)

    return msg


def port465(args, message, host, port):
    """Log in to server using secure context from the onset and send email. This uses SSL/TLS."""
    with smtplib.SMTP_SSL(host, port, context=context, timeout=30) as server:
        if args.verbose:
            server.set_debuglevel(2)
        if args.username:
            server.login(args.username, args.password)
        # send_message() annoymizes BCC, rather than sendmail().
        server.send_message(message)
        print("Message sent")


def port25(args, message, host, port):
    """Create an unsecured connection, then secure it, and then send email. This uses startTLS."""
    with smtplib.SMTP(host, port, timeout=30) as server:
        if args.verbose:
            server.set_debuglevel(2)
        if args.starttls:
            server.starttls(context=context)
        if args.username:
            server.login(args.username, args.password)
        # send_message() annoymizes BCC, rather than sendmail().
        server.send_message(message)
        print("Message sent")


def sendEmail(args, fromaddress, host, port):
    """This function compiles our (optionally signed) message and calls the correct send function according to what port is entered."""
    if args.dryrun:
        return
    if args.time:
        time.sleep(args.time)
    lang, _ = locale.getlocale()
    # S/MIME
    if args.cert:
        message = smime.smime(args, lang)
    # PGP
    elif args.passphrase:
        message = pgp.pgp(args, fromaddress, lang)
    # No signing of message
    else:
        message = send_normal(args, lang)

    # Debug code
    # print(message.as_string(policy=message.policy.clone(utf8=True)))
    # print(message)
    # sys.exit(0)

    try:
        if args.tls:
            port465(args, message, host, port)
        else:
            port25(args, message, host, port)

    except socket.timeout as e:
        print(f"{type(e).__name__}: {e}")
        print(
            "Connection timed out when trying to connect. Please verify the server is up or you entered the correct port number for the SMTP server."
        )
        sys.exit(2)
    except smtplib.SMTPHeloError as e:
        print(f"{type(e).__name__}: {e}")
        print("Server did not reply. You may have Port 25 blocked on your host machine.")
        sys.exit(2)
    except smtplib.SMTPAuthenticationError as e:
        print(f"{type(e).__name__}: {e}")
        print(
            "Incorrect username/password combination or, if you are using Gmail, you may need to lower the security settings or login from this computer (see the README.md for more information)."
        )
        sys.exit(2)
    except (OSError, ssl.CertificateError, smtplib.SMTPException) as e:
        print(f"{type(e).__name__}: {e}")
        sys.exit(2)
