#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2013, Peter Facka
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import os
import os.path
import smtplib
import datetime

from M2Crypto import BIO, Rand, SMIME
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
#from email.Utils import COMMASPACE, formatdate
from email.utils import formatdate
from email import encoders
#from email import Encoders

# we need to have access to both keys
ssl_key = 'cert.key'
ssl_cert = 'cert.crt'


def send_mail_ssl(server, sender, to, subject, text, files=[], attachments={}, bcc=[]):
    """
    Sends SSL signed mail

    server - mailserver domain name eg. smtp.foo.bar
    sender - content of From field eg. "No Reply" <noreply@foo.bar>
    to - list of strings with email addresses of recipents
    subject - subject of a mail
    text - text of email
    files - list of strings with paths to file to be attached
    attachmets - dict where keys are file names and values are content of files
    to be attached
    bcc - list of strings with blind copy addresses
    """

    if isinstance(to,str):
        to = [to]

    # create multipart message
    msg = MIMEMultipart()

    # attach message text as first attachment
    msg.attach( MIMEText(text) )

    # attach files to be read from file system
    for file in files:
        part = MIMEBase('application', "octet-stream")
        part.set_payload( open(file,"rb").read() )
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"'
                       % os.path.basename(file))
        msg.attach(part)

    # attach filest read from dictionary
    for name in attachments:
        part = MIMEBase('application', "octet-stream")
        part.set_payload(attachments[name])
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % name)
        msg.attach(part)

    # put message with attachments into into SSL' I/O buffer
    msg_str = msg.as_string()
    #print(msg_str)
    #buf = BIO.MemoryBuffer(msg_str)
    buf = BIO.MemoryBuffer(msg.as_bytes())

    # load seed file for PRNG
    #Rand.load_file('/tmp/randpool.dat', -1)
    Rand.load_file('cert.pem', -1)

    smime = SMIME.SMIME()

    # load certificate
    smime.load_key(ssl_key, ssl_cert)

    # sign whole message
    p7 = smime.sign(buf, SMIME.PKCS7_DETACHED)

    # create buffer for final mail and write header
    out = BIO.MemoryBuffer()
    out.write('From: %s\n' % sender)
    out.write('To: ' + ", ".join(to))
            #%s\n' % COMMASPACE.join(to))
    out.write('Date: %s\n' % formatdate(localtime=True))
    out.write('Subject: %s\n' % subject)
    out.write('Auto-Submitted: %s\n' % 'auto-generated')

    # convert message back into string
    #buf = BIO.MemoryBuffer(msg_str)
    buf = BIO.MemoryBuffer(msg.as_bytes())

    # append signed message and original message to mail header
    smime.write(out, p7, buf)

    # load save seed file for PRNG
    Rand.save_file('/tmp/randpool.dat')

    # extend list of recipents with bcc adresses
    to.extend(bcc)

    # finaly send mail
    '''
    smtp = smtplib.SMTP(server)
    smtp.sendmail(sender, to, out.read() )
    smtp.close()
    '''
    import ssl
    context = ssl.create_default_context()
    print("HERE")
    print(context)
    with smtplib.SMTP_SSL(server, 465, context=context) as server:
        server.login(sender, "Rainforesttri265!")
        server.sendmail(sender, to, out.read()) # send_message() annoymizes BCC, rather than sendmail().
        #server.send_message(out.read()) # send_message() annoymizes BCC, rather than sendmail().

send_mail_ssl("smtp.gmail.com", "danc2@pdx.edu", "connellyd2050@gmail.com", "SMIME TEST", "This is a test", files=["send.py"], attachments={}, bcc=["danc2@pdx.edu"])

