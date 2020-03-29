# Output usage
# usage <program name>
sendmsg = "python3 sendmsg.py"
def usage():
    #sendmsg = "python3 sendmsg.py"
    print(f'Usage: {sendmsg} <OPTION(S)>... -s <subject>\n'+
    "One or more 'To', 'CC' or 'BCC' e-mail addresses are required. Send text messages by using the mobile providers e-mail to SMS or MMS gateway (https://en.wikipedia.org/wiki/SMS_gateway#Email_clients). See examples below.\n"+

    "Options:\n\n"+
        "    -a --attachments Attachment filename\n"+
                            "Use multiple times for multiple attachments. Supports Unicode characters in filename.\n"+
        "    -b --bccemails BCC e-mail address(es)\n"+
        "    -c --ccemails    CC e-mail address(es)\n"+
        "    -C --certificate S/MIME Certificate filename for digitally signing the e-mails\n"+
        "    -d --dryrun     Dry run, do not send the e-mail\n"+
                            "It will ask you for the password the first time you run the script with this option. Requires SMTP server.\n"+
        "    -e --examples   Show example usages for this script\n"+
        "    -f --fromemail From e-mail address\n"+
        "    -h --help       Display this help and exit\n"+
        "    -k --passphrase PGP secret key passphrase for digitally signing the e-mails with PGP/MIME\n"+
                            "Requires SMTP server.\n"+
        "    -m --message      Message body\n"+
                             "Escape sequences are expanded. Supports Unicode characters.\n"+
        "    -p --password   SMTP server password\n"+
        "    -P --priority   Priority\n"+
                            "Supported priorities: \"5 (Lowest)\", \"4 (Low)\", \"3 (Normal)\", \"2 (High)\" and \"1 (Highest)\". Requires SMTP server.\n"+
        "    -s, --subject    Subject\n"+
                            "Escape sequences are expanded. Supports Unicode characters.\n"+
        "    -t --toemails    To e-mail address(es)\n"+

        "    -u --username   SMTP server username\n"+
        "    -v --version    Output version information and exit\n\n"+
        "    -V --verbose    Verbose, show the client-server communication\n"+
                            "Requires SMTP server.\n"+
        "    -z --zipfile    Compress attachment(s) with zip")

def examples():
    print("Sendmsg Examples:\n"+
        "    Send e-mail\n"+
        f'    $ {sendmsg} -s \"Example\" -t \"Example <example@example.com>\"\n\n'+

        "    Send e-mail with message\n"+
        f'    $ {sendmsg} -s \"Example\" -m \"This is an example!\" -t \"Example <example@example.com>\"\n\n'+

        "    Send e-mail with message and single attachment\n"+
        "    $ python3 sendmsg -s \"Example\" -m \"This is an example"'!'"\" -a example.txt -t \"Example <example@example.com>\"\n\n"+

        "    Send e-mail with message and multiple attachments\n"+
        f'    $ {sendmsg} -s \"Example\" -m \"This is an example!\" -a example1.txt -a example2.txt -t \"Example <example@example.com>\"\n\n'+

        "    Send e-mail to a CC address\n"+
        f'    $ {sendmsg} -s \"Example\" -t \"Example 1 <example1@example.com>\" -c \"Example 2 <example2@example.com>\"\n\n'+

        "    Send e-mail with a From address\n"+
        f'    $ {sendmsg} -s \"Example\" -f \"Example <example@example.com>\" -t \"Example <example@example.com>\"\n\n'+

        "    Send e-mail with an external SMTP server\n"+
        f'    $ {sendmsg} -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -t \"Example <example@example.com>\"\n\n'+

        "    Send high priority e-mail\n"+
        f'    $ {sendmsg} -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -P \"1 (Highest)\" -t \"Example <example@example.com>\"\n\n'+

        "    Send e-mail digitally signed with an S/MIME Certificate\n"+
        f'    $ {sendmsg} -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -C \"cert.p12\" -t \"Example <example@example.com>\"\n\n'+

        f'    Send e-mail digitally signed with PGP/MIME"+ "{sendmsg} -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -k \"passphrase\" -t \"Example <example@example.com>\"')

