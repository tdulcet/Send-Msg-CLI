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

if sys.platform == "win32":
    import glob

    for file in glob.iglob(os.path.join(os.path.dirname(sys.executable), "DLLs", "libcrypto*.dll")):
        libcrypto = file
        break
    else:
        libcrypto = find_library("libcrypto") or find_library("libeay32")
else:
    libcrypto = find_library("crypto") or find_library("eay32")
crypto = None
if libcrypto:
    crypto = ctypes.CDLL(libcrypto)

    crypto.BIO_new_file.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
    crypto.BIO_new_file.restype = ctypes.c_void_p

    crypto.d2i_PKCS12_bio.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    crypto.d2i_PKCS12_bio.restype = ctypes.c_void_p

    crypto.BIO_free.argtypes = (ctypes.c_void_p,)
    # crypto.BIO_free.restype = ctypes.c_int

    crypto.PKCS12_parse.argtypes = (
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    # crypto.PKCS12_parse.restype = ctypes.c_int

    crypto.PKCS12_free.argtypes = (ctypes.c_void_p,)
    # crypto.PKCS12_free.restype = None

    crypto.PEM_write_bio_PrivateKey.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    # crypto.PEM_write_bio_PrivateKey.restype = ctypes.c_int

    crypto.PEM_write_bio_X509.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    # crypto.PEM_write_bio_X509.restype = ctypes.c_int

    crypto.X509_free.argtypes = (ctypes.c_void_p,)
    # crypto.X509_free.restype = None

    crypto.EVP_PKEY_free.argtypes = (ctypes.c_void_p,)
    # crypto.EVP_PKEY_free.restype = None

    crypto.PEM_read_bio_X509.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p)
    crypto.PEM_read_bio_X509.restype = ctypes.c_void_p

    crypto.X509_get_issuer_name.argtypes = (ctypes.c_void_p,)
    crypto.X509_get_issuer_name.restype = ctypes.c_void_p

    crypto.X509_NAME_get_index_by_NID.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_int)
    # crypto.X509_NAME_get_index_by_NID.restype = ctypes.c_int

    crypto.X509_NAME_get_entry.argtypes = (ctypes.c_void_p, ctypes.c_int)
    crypto.X509_NAME_get_entry.restype = ctypes.c_void_p

    crypto.X509_NAME_ENTRY_get_data.argtypes = (ctypes.c_void_p,)
    crypto.X509_NAME_ENTRY_get_data.restype = ctypes.c_void_p

    crypto.ASN1_STRING_to_UTF8.argtypes = (ctypes.POINTER(ctypes.c_char_p), ctypes.c_void_p)
    # crypto.ASN1_STRING_to_UTF8.restype = ctypes.c_int

    crypto.CRYPTO_free.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int)
    # crypto.CRYPTO_free.restype = None

    # crypto.BIO_s_mem.argtypes = ()
    crypto.BIO_s_mem.restype = ctypes.c_void_p

    crypto.BIO_new.argtypes = (ctypes.c_void_p,)
    crypto.BIO_new.restype = ctypes.c_void_p

    crypto.BIO_gets.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int)
    # crypto.BIO_gets.restype = ctypes.c_int

    if hasattr(crypto, "X509_get0_notAfter"):
        X509_get0_notAfter = crypto.X509_get0_notAfter
        X509_get0_notAfter.argtypes = (ctypes.c_void_p,)
        X509_get0_notAfter.restype = ctypes.c_void_p
    else:

        class X509_VAL(ctypes.Structure):
            _fields_ = (("notBefore", ctypes.c_void_p), ("notAfter", ctypes.c_void_p))

        class X509_CINF(ctypes.Structure):
            _fields_ = (
                ("version", ctypes.c_void_p),
                ("serialNumber", ctypes.c_void_p),
                ("signature", ctypes.c_void_p),
                ("issuer", ctypes.c_void_p),
                ("validity", ctypes.POINTER(X509_VAL)),
                # ("subject", ctypes.c_void_p),
            )

        class X509(ctypes.Structure):
            _fields_ = (("cert_info", ctypes.POINTER(X509_CINF)),)

        def X509_get0_notAfter(x509):
            x = X509.from_address(x509)
            return x.cert_info.contents.validity.contents.notAfter

    crypto.ASN1_TIME_print.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    # crypto.ASN1_TIME_print.restype = ctypes.c_int

    crypto.BIO_ctrl.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p)
    crypto.BIO_ctrl.restype = ctypes.c_long

    crypto.PEM_read_bio_PrivateKey.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p)
    crypto.PEM_read_bio_PrivateKey.restype = ctypes.c_void_p

    crypto.BIO_new_mem_buf.argtypes = (ctypes.c_void_p, ctypes.c_int)
    crypto.BIO_new_mem_buf.restype = ctypes.c_void_p

    crypto.CMS_sign.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint)
    crypto.CMS_sign.restype = ctypes.c_void_p

    crypto.SMIME_write_CMS.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)
    # crypto.SMIME_write_CMS.restype = ctypes.c_int

    crypto.CMS_ContentInfo_free.argtypes = (ctypes.c_void_p,)
    # crypto.CMS_ContentInfo_free.restype = None

    # crypto.ERR_get_error.argtypes = ()
    crypto.ERR_get_error.restype = ctypes.c_ulong

    # crypto.ERR_error_string.argtypes = (ctypes.c_ulong, ctypes.c_char_p)
    # crypto.ERR_error_string.restype = ctypes.c_char_p

    crypto.ERR_lib_error_string.argtypes = (ctypes.c_ulong,)
    crypto.ERR_lib_error_string.restype = ctypes.c_char_p

    crypto.ERR_reason_error_string.argtypes = (ctypes.c_ulong,)
    crypto.ERR_reason_error_string.restype = ctypes.c_char_p

    def ssl_error(errstr):
        errcode = crypto.ERR_get_error()
        lib_str = crypto.ERR_lib_error_string(errcode)
        reason_str = crypto.ERR_reason_error_string(errcode)

        if reason_str and lib_str:
            msg = f"[{lib_str}: {reason_str}] {errstr}"
        elif lib_str:
            msg = f"[{lib_str}] {errstr}"
        else:
            msg = errstr

        return ssl.SSLError(errcode & 0xFFF, msg)


def cert_checks(args, now):
    """Creates the .pem certificate (defined in CLIENTCERT; e.g., cert.pem) with certificate \
       located in args.cert (read in from CMDLINE using -C, or --cert).
    """
    if crypto is None:
        msg = "OpenSSL is not installed"
        raise RuntimeError(msg)

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
            raise ssl_error(msg)
        try:
            p12 = crypto.d2i_PKCS12_bio(file, None)
            if not p12:
                msg = "Failed to read PKCS12 file"
                raise ssl_error(msg)
        finally:
            crypto.BIO_free(file)

        passphrase = getpass.getpass("Import Password: ")
        pkey = ctypes.c_void_p()
        cert = ctypes.c_void_p()

        if crypto.PKCS12_parse(p12, passphrase.encode(), ctypes.byref(pkey), ctypes.byref(cert), None) != 1:
            msg = "Failed to parse PKCS12 file, likely bad Password"
            raise ssl_error(msg)

        crypto.PKCS12_free(p12)

        out = crypto.BIO_new_file(CLIENTCERT.encode(), b"w")
        if not out:
            msg = "Failed to open file for writing"
            raise ssl_error(msg)
        try:
            if crypto.PEM_write_bio_PrivateKey(out, pkey, None, None, 0, None, None) != 1:
                msg = "Failed to write private key"
                raise ssl_error(msg)

            if crypto.PEM_write_bio_X509(out, cert) != 1:
                msg = "Failed to write certificate"
                raise ssl_error(msg)
        finally:
            crypto.BIO_free(out)

        crypto.X509_free(cert)
        crypto.EVP_PKEY_free(pkey)

    file = crypto.BIO_new_file(CLIENTCERT.encode(), b"r")
    if not file:
        msg = "Failed to open file"
        raise ssl_error(msg)
    try:
        cert = crypto.PEM_read_bio_X509(file, None, None, None)
        if not cert:
            msg = "Failed to load certificate"
            raise ssl_error(msg)
    finally:
        crypto.BIO_free(file)

    issuer = None
    # ["openssl", "x509", "-in", CLIENTCERT, "-noout", "-issuer", "-nameopt", "multiline,-align,-esc_msb,utf8,-space_eq"]
    aissuer = crypto.X509_get_issuer_name(cert)

    lastpos = crypto.X509_NAME_get_index_by_NID(aissuer, 17, -1)  # NID_organizationName
    if lastpos == -1:
        lastpos = crypto.X509_NAME_get_index_by_NID(aissuer, 13, -1)  # NID_commonName

    if lastpos != -1:
        entry = crypto.X509_NAME_get_entry(aissuer, lastpos)
        value = crypto.X509_NAME_ENTRY_get_data(entry)
        buffer = ctypes.c_char_p()
        length = crypto.ASN1_STRING_to_UTF8(ctypes.byref(buffer), value)
        if length < 0:
            msg = "ASN1_STRING_to_UTF8 failed"
            raise ssl_error(msg)

        try:
            issuer = ctypes.string_at(buffer, length).decode()
        finally:
            # crypto.OPENSSL_free(buffer)
            crypto.CRYPTO_free(buffer, None, 0)

    # ["openssl", "x509", "-in", CLIENTCERT, "-noout", "-enddate"]
    adate = X509_get0_notAfter(cert)

    out = crypto.BIO_new(crypto.BIO_s_mem())
    if not out:
        msg = "Failed to create BIO"
        raise ssl_error(msg)

    if crypto.ASN1_TIME_print(out, adate) != 1:
        msg = "Failed to print end date"
        raise ssl_error(msg)

    buf = ctypes.create_string_buffer(64)
    crypto.BIO_gets(out, buf, len(buf))
    date = buf.value.decode()

    crypto.BIO_free(out)
    crypto.X509_free(cert)

    # datetime.strptime(date, "%b %d %H:%M:%S %Y %Z")
    date = datetime.fromtimestamp(ssl.cert_time_to_seconds(date))

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
        raise ssl_error(msg)
    try:
        cert = crypto.PEM_read_bio_X509(file, None, None, None)
        if not cert:
            msg = "Failed to load certificate"
            raise ssl_error(msg)

        if crypto.BIO_ctrl(file, 1, 0, None):  # BIO_CTRL_RESET # BIO_reset(file)
            raise ssl_error

        skey = crypto.PEM_read_bio_PrivateKey(file, None, None, None)
        if not skey:
            msg = "Failed to load private key"
            raise ssl_error(msg)
    finally:
        crypto.BIO_free(file)

    data = msg.as_bytes(policy=SMTP)
    ain = crypto.BIO_new_mem_buf(data, len(data))
    if not ain:
        msg = "Failed to create BIO for data"
        raise ssl_error(msg)

    flags = 0x40 | 0x1000  # CMS_STREAM | CMS_DETACHED
    cms = crypto.CMS_sign(cert, skey, None, ain, flags)
    if not cms:
        msg = "Failed to sign data"
        raise ssl_error(msg)

    out = crypto.BIO_new(crypto.BIO_s_mem())
    if not out:
        msg = "Failed to create BIO for output"
        raise ssl_error(msg)

    if crypto.SMIME_write_CMS(out, cms, ain, flags) != 1:
        msg = "Failed to output CMS data"
        raise ssl_error(msg)

    buffer = ctypes.c_char_p()
    # length = crypto.BIO_get_mem_data(out, ctypes.byref(buffer))
    length = crypto.BIO_ctrl(out, 3, 0, ctypes.byref(buffer))  # BIO_CTRL_INFO
    if length < 0:
        msg = "BIO_get_mem_data failed"
        raise ssl_error(msg)
    cert_sig = ctypes.string_at(buffer, length)

    crypto.X509_free(cert)
    crypto.EVP_PKEY_free(skey)
    crypto.BIO_free(ain)
    crypto.BIO_free(out)
    crypto.CMS_ContentInfo_free(cms)

    message = email.message_from_bytes(cert_sig, policy=default)

    send.set_main_headers(args, message)

    return message
