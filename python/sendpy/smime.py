import ctypes
import email
import getpass
import os
import ssl
import sys
from ctypes.util import find_library
from datetime import datetime, timedelta
from email.message import MIMEPart
from email.policy import SMTP, default

import send

CLIENTCERT = "cert.pem"
WARNDAYS = 3

# libcrypto = find_library("libeay32" if sys.platform == "win32" else "crypto")
libcrypto = find_library("libcrypto" if sys.platform == "win32" else "crypto")
crypto = None
if libcrypto:
    crypto = ctypes.CDLL(libcrypto)

    crypto.BIO_s_mem.restype = ctypes.c_void_p
    crypto.BIO_new.argtypes = (ctypes.c_void_p,)

    # crypto.ERR_error_string.restype = ctypes.c_char_p


def cert_checks(args, now):
    """Creates the .pem certificate (defined in CLIENTCERT; e.g., cert.pem) with certificate \
       located in args.cert (read in from CMDLINE using -C, or --cert).
    """
    if crypto is None:
        print("Error: OpenSSL is not installed.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.cert) and not os.path.exists(CLIENTCERT):
        print(f"Error: {args.cert!r} certificate file does not exist.", file=sys.stderr)
        sys.exit(1)

    if not (os.path.exists(CLIENTCERT) and os.path.getsize(CLIENTCERT)):
        print(f"Saving the client certificate from {args.cert!r} to {CLIENTCERT!r}")
        print("Please enter the password when prompted.\n")

        # ["openssl", "pkcs12", "-in", args.cert, "-out", CLIENTCERT, "-clcerts", "-nodes"]
        file = crypto.BIO_new_file(args.cert.encode(), b"r")
        if not file:
            msg = "Failed to open file"
            raise ssl.SSLError(msg)

        p12 = crypto.d2i_PKCS12_bio(file, None)
        if not p12:
            msg = "Failed to read PKCS12 file"
            raise ssl.SSLError(msg)

        crypto.BIO_free(file)

        passphrase = getpass.getpass("Import Password: ")
        pkey = ctypes.c_void_p()
        cert = ctypes.c_void_p()

        if crypto.PKCS12_parse(p12, passphrase.encode(), ctypes.byref(pkey), ctypes.byref(cert), None) != 1:
            msg = "Failed to parse PKCS12 file"
            raise ssl.SSLError(msg)

        crypto.PKCS12_free(p12)

        out = crypto.BIO_new_file(CLIENTCERT.encode(), b"w")
        if not out:
            msg = "Failed to open file for writing"
            raise ssl.SSLError(msg)

        if crypto.PEM_write_bio_PrivateKey(out, pkey, None, None, 0, None, None) != 1:
            msg = "Failed to write private key"
            raise ssl.SSLError(msg)

        if crypto.PEM_write_bio_X509(out, cert) != 1:
            msg = "Failed to write certificate"
            raise ssl.SSLError(msg)

        crypto.BIO_free(out)
        crypto.X509_free(cert)
        crypto.EVP_PKEY_free(pkey)

    file = crypto.BIO_new_file(CLIENTCERT.encode(), b"r")
    if not file:
        msg = "Failed to open file"
        raise ssl.SSLError(msg)

    cert = crypto.PEM_read_bio_X509(file, None, None, None)
    if not cert:
        msg = "Failed to load certificate"
        raise ssl.SSLError(msg)

    crypto.BIO_free(file)

    issuer = None
    # ["openssl", "x509", "-in", CLIENTCERT, "-noout", "-issuer", "-nameopt", "multiline,-align,-esc_msb,utf8,-space_eq"]
    aissuer = crypto.X509_get_issuer_name(cert)

    lastpos = crypto.X509_NAME_get_index_by_NID(aissuer, 17, -1)  # NID_organizationName
    if lastpos == -1:
        lastpos = crypto.X509_NAME_get_index_by_NID(aissuer, 13, -1)  # NID_commonName

    if lastpos != -1:
        e = crypto.X509_NAME_get_entry(aissuer, lastpos)
        d = crypto.X509_NAME_ENTRY_get_data(e)
        out = crypto.BIO_new(crypto.BIO_s_mem())
        if not out:
            msg = "Failed to create BIO"
            raise ssl.SSLError(msg)

        length = crypto.ASN1_STRING_print_ex(out, d, 0x10)  # ASN1_STRFLGS_UTF8_CONVERT
        if length < 0:
            msg = "Failed to print issuer name"
            raise ssl.SSLError(msg)

        buf = ctypes.create_string_buffer(length)
        crypto.BIO_read(out, buf, len(buf))
        issuer = buf.value.decode()

        crypto.BIO_free(out)

    # ["openssl", "x509", "-in", CLIENTCERT, "-noout", "-enddate"]
    adate = crypto.X509_get0_notAfter(cert)

    out = crypto.BIO_new(crypto.BIO_s_mem())
    if not out:
        msg = "Failed to create BIO"
        raise ssl.SSLError(msg)

    if crypto.ASN1_TIME_print(out, adate) != 1:
        msg = "Failed to print end date"
        raise ssl.SSLError(msg)

    buf = ctypes.create_string_buffer(128)
    crypto.BIO_read(out, buf, len(buf))
    date = buf.value.decode()

    crypto.BIO_free(out)
    crypto.X509_free(cert)

    date = datetime.strptime(date, "%b %d %H:%M:%S %Y %Z")

    if date > now:
        delta = date - now
        warn = timedelta(days=WARNDAYS)
        if delta < warn:
            print(
                f"Warning: The S/MIME Certificate {f'from “{issuer}” ' if issuer else ''}expires in less than {WARNDAYS} days ({date:%c}).\n"
            )
    else:
        print(f"Error: The S/MIME Certificate {f'from “{issuer}” ' if issuer else ''}expired {date:%c}.", file=sys.stderr)
        sys.exit(1)


def smime(args, lang):
    """Signs message + attachments with S/MIME protocol."""
    msg = MIMEPart()
    if args.message:
        msg.set_content(args.message, cte="quoted-printable")
    if args.language and lang:
        msg["Content-Language"] = lang.replace("_", "-")

    if args.attachments:
        send.attachments(msg, args.attachments)

    # ["openssl", "cms", "-sign", "-signer", CLIENTCERT],
    file = crypto.BIO_new_file(CLIENTCERT.encode(), b"r")
    if not file:
        msg = "Failed to open file"
        raise ssl.SSLError(msg)

    cert = crypto.PEM_read_bio_X509(file, None, None, None)
    if not cert:
        msg = "Failed to load certificate"
        raise ssl.SSLError(msg)

    if crypto.BIO_ctrl(file, 1, 0, None):  # BIO_CTRL_RESET # BIO_reset(file)
        raise ssl.SSLError

    skey = crypto.PEM_read_bio_PrivateKey(file, None, None, None)
    if not skey:
        msg = "Failed to load private key"
        raise ssl.SSLError(msg)

    crypto.BIO_free(file)

    data = msg.as_bytes(policy=SMTP)
    ain = crypto.BIO_new_mem_buf(data, len(data))
    if not ain:
        msg = "Failed to create BIO for data"
        raise ssl.SSLError(msg)

    flags = 0x40 | 0x1000  # CMS_STREAM | CMS_DETACHED
    cms = crypto.CMS_sign(cert, skey, None, ain, flags)
    if not cms:
        msg = "Failed to sign data"
        raise ssl.SSLError(msg)

    out = crypto.BIO_new(crypto.BIO_s_mem())
    if not out:
        msg = "Failed to create BIO for output"
        raise ssl.SSLError(msg)

    if crypto.SMIME_write_CMS(out, cms, ain, flags) != 1:
        msg = "Failed to output CMS data"
        raise ssl.SSLError(msg)

    buf = ctypes.create_string_buffer(1024 * 1024)
    cert_sig = bytearray()
    while True:
        readbytes = crypto.BIO_read(out, buf, len(buf))
        if readbytes <= 0:
            break
        cert_sig.extend(buf.raw[:readbytes])

    crypto.X509_free(cert)
    crypto.EVP_PKEY_free(skey)
    crypto.BIO_free(ain)
    crypto.BIO_free(out)
    crypto.CMS_ContentInfo_free(cms)

    message = email.message_from_bytes(cert_sig, policy=default)

    send.set_main_headers(args, message)

    return message
