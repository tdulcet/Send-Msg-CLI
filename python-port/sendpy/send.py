import email
import locale
import mimetypes
import os
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from email.message import EmailMessage, MIMEPart
from email.policy import SMTP, default
from email.utils import localtime

"""Copyright © Daniel Connelly and Teal Dulcet

   The purpose of this file is to fill a MIME object, possibly with sub MIME objects, with the necessary
   values/attachments/keys to send the message requested by the user.
"""


def set_main_headers(args, message):
    """Set common headers in every email."""
    COMMASPACE = ", "
    message["User-Agent"] = "Send Msg CLI/SendPy"
    message["From"] = args.fromemail
    message["To"] = "undisclosed-recipients:;" if not args.toemails and not args.ccemails else COMMASPACE.join(
        args.toemails)
    if args.ccemails:
        message["Cc"] = COMMASPACE.join(args.ccemails)
    if args.bccemails:
        message["Bcc"] = COMMASPACE.join(args.bccemails)
    message["Subject"] = args.subject
    message["Date"] = datetime.fromtimestamp(int(datetime.now(
    ).timestamp()) // 60 * 60, timezone.utc) if args.utc else localtime()
    if args.priority:
        message["X-Priority"] = args.priority
    if args.mdn:
        message["Disposition-Notification-To"] = args.fromemail
    return message


def attachments(message, aattachments):
    """Create a MIMEApplication method with our attachment as a payload and then attach it to our main message."""
    for file in aattachments:
        ctype, encoding = mimetypes.guess_type(file)
        if ctype is None or encoding is not None:
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        with open(file, "rb") as f:
            message.add_attachment(
                f.read(), maintype=maintype, subtype=subtype, filename=os.path.basename(file))


def smime(args, clientcert, lang):
    """Signs message + attachments with S/MIME protocol."""
    msg = MIMEPart()
    if args.message:
        msg.set_content(args.message, cte="quoted-printable")
    if args.language and lang:
        msg["Content-Language"] = lang.replace("_", "-")

    if args.attachments:
        attachments(msg, args.attachments)

    cert_sig = subprocess.check_output(
        ["openssl", "cms", "-sign", "-signer", clientcert], input=msg.as_bytes(policy=SMTP))

    message = email.message_from_bytes(cert_sig, policy=default)

    set_main_headers(args, message)

    return message


def pgp(args, fromaddress, lang):
    """Signs message + attachments with PGP key."""
    msg = MIMEPart()
    if args.message:
        msg.set_content(args.message, cte="quoted-printable")
    if args.language and lang:
        msg["Content-Language"] = lang.replace("_", "-")

    if args.attachments:
        attachments(msg, args.attachments)

    with tempfile.NamedTemporaryFile("wb") as f:
        f.write(msg.as_bytes(policy=SMTP))
        # f.flush()

        pgp_sig = subprocess.check_output(["gpg", "--pinentry-mode", "loopback", "--batch", "-o", "-",
                                          "-ab", "-u", fromaddress, "--passphrase-fd", "0", f.name], input=args.passphrase.encode())

    signmsg = EmailMessage()
    signmsg.make_mixed()
    signmsg.attach(msg)
    signmsg.add_attachment(pgp_sig, maintype="application",
                           subtype="pgp-signature", filename="signature.asc")
    signmsg.replace_header(
        "Content-Type", 'multipart/signed; protocol="application/pgp-signature"; micalg=pgp-sha1')

    set_main_headers(args, signmsg)

    return signmsg


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
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(host, port, context=context, timeout=30) as server:
        if args.verbose:
            server.set_debuglevel(2)
        if args.username:
            server.login(args.username, args.password)
        # send_message() annoymizes BCC, rather than sendmail().
        server.send_message(message)
        print("Message sent")


def port587(args, message, host, port):
    """Create an unsecured connection, then secure it, and then send email. This uses startTLS."""
    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=30) as server:
        if args.verbose:
            server.set_debuglevel(2)
        server.starttls(context=context)
        if args.username:
            server.login(args.username, args.password)
        # send_message() annoymizes BCC, rather than sendmail().
        server.send_message(message)
        print("Message sent")


def port25(args, message, host, port):
    """Use a local SMTP server connection to send email."""
    with smtplib.SMTP(host, port, timeout=30) as server:
        if args.verbose:
            server.set_debuglevel(2)
        if args.username:
            server.login(args.username, args.password)
        # send_message() annoymizes BCC, rather than sendmail().
        server.send_message(message)
        print("Message sent")


def sendEmail(args, clientcert, fromaddress, host, port):
    """This function compiles our (optionally signed) message and calls the correct send function according to what port is entered."""
    if args.dryrun:
        return
    if args.time:
        time.sleep(args.time)
    lang, _ = locale.getlocale()
    # S/MIME
    if args.cert:
        message = smime(args, clientcert, lang)
    # PGP
    elif args.passphrase:
        message = pgp(args, fromaddress, lang)
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
        elif args.starttls:
            port587(args, message, host, port)
        else:
            port25(args, message, host, port)

    except socket.timeout:
        print("Connection timed out when trying to connect. Please verify the server is up or you entered the correct port number for the SMTP server.")
    except smtplib.SMTPHeloError:
        print("Server did not reply. You may have Port 25 blocked on your host machine.")
        sys.exit(2)
    except smtplib.SMTPAuthenticationError as e:
        print(e)
        print("Incorrect username/password combination or, if you are using Gmail, you may need to lower the security settings or login from this computer (see the README.md for more information).")
        sys.exit(2)
    except smtplib.SMTPException as e:
        print(e)
        print("Authentication failed.")
        sys.exit(2)
