# Output usage
# usage <program name>
import sys
sendmsg = sys.argv[0]

from sendmsg import format_attachment_output # this prints out our help menu in an even format.
from sendmsg import decode_escapes

def usage():
    # Bottom three print statements have to be printed separately so as not to affect the ...
    print(f"Usage: {sendmsg} <OPTION(S)>... -S <smtp server> -t <To address> -f <From address> -u 'username' -p 'password'", "")
    print(f'or: {sendmsg} <OPTION>')
    print(f"One or more 'To', 'CC' or 'BCC' e-mail addresses are required. Send text messages by using the mobile providers e-mail to SMS or MMS gateway (https://en.wikipedia.org/wiki/SMS_gateway#Email_clients). See examples by using the -e or --examples option.", "\n")

    # Then we create a row and print it
    format_attachment_output([
    ("Options:\nMandatory arguments to long options are mandatory for short options too.", ''),
    ("    -a, --attachment <attachment>", "Attachment filename"),
        (" ", "-Use multiple times for multiple attachments. Supports Unicode characters in filename."),
    ("    -b, --bccemails <address>", "BCC e-mail address"),
        (" ", "-Use multiple times for multiple BCC addresses."),
    ("    -c, --ccemails <address>",  "CC e-mail address"),
        (" ", "-Use multiple times for multiple CC addresses."),
    ("    --config",  "Configure default flags to include everytime you run sendpy. Namely, smtp server (-S), from (-f), username (-u), and password (-p)."),
    ("    -C, --certificate <file path>", "S/MIME Certificate filename for digitally signing the e-mails"),
        (" ", "-It will ask you for the password the first time you run the script with this option."),
    ("    -d, --dryrun", "Dry run, do not send the e-mail"),
    ("    -e, --examples","Show example usages for this script"),
    ("    -f, --fromemail <address>", "From e-mail address"),
    ("    -g, --gateways", "Displays a non-complete listing of SMS and MMS Gateways for the US and Canada, then exits"),
    ("    -h, --help", "Display this help and exit"),
    ("    -k, --passphrase <passphrase>", "PGP secret key passphrase for digitally signing the e-mails with PGP/MIME"),
    ("    -m, --message <message>",      "Message body"),
        (" ", "-Escape sequences are expanded. Supports Unicode characters."),
    ("    -p, --password <password>",   "SMTP server password"),
    ("    -P, --priority <priority>",   "Priority"),
        (" ", "-Supported priorities: '5 (Lowest)', '4 (Low)', 'Normal', '2 (High)' and '1 (Highest)'."),
    ("    -s, --subject <subject>",    "Subject"),
        (" ", "-Escape sequences are expanded. Supports Unicode characters."),
    ("    -S, --smtp <server>", "SMTP server"),
    (" ", '-Supported protocols: "smtp" and "smtps". Use "localhost:25" if running a mail server on this device.'),
    ("    -t, --toemail <address>",    "To e-mail address(es)"),
        (" ", "-Use multiple times for multiple TO addresses."),

    ("    -u, --username <username>, ",   "SMTP server username"),
    ("    -v, --version",    "Output version information and exit"),
    ("    -V, --verbose",    "Verbose, show the client-server communication"),
    ("    -z, --zipfile <filename>",    "Compress attachment(s) with zip\n")])

def examples():
    print("Sendmsg Examples:\n"+
        "    Send e-mail\n"+
        f'    $ {sendmsg} -s \"Example\" -t \"Example <example@example.com>\"\n\n'+

        "    Send e-mail with message\n"+
        f'    $ {sendmsg} -s \"Example\" -m \"This is an example!\" -t \"Example <example@example.com>\"\n\n'+

        "    Send e-mail with message and single attachment\n"+
        f'    $ {sendmsg} -s \"Example\" -m \"This is an example!" -a "example.txt" -t \"Example <example@example.com>\"\n\n'+

        "    Send e-mail with message and multiple attachments\n"+
        f'    $ {sendmsg} -s \"Example\" -m \"This is an example!\" -a "example1.txt" -a example2.txt -t \"Example <example@example.com>\"\n\n'+

        "    Send e-mail to a CC address\n"+
        f'    $ {sendmsg} -s \"Example\" -t \"Example 1 <example1@example.com>\" -c \"Example 2 <example2@example.com>\"\n\n'+

        "    Send e-mail with a From address\n"+
        f'    $ {sendmsg} -s \"Example\" -f \"Example <example@example.com>\" -t \"Example <example@example.com>\"\n\n'+

        "    Send high priority e-mail\n"+
        f'    $ {sendmsg} -s \"Example\" -f \"Example <example@example.com>\" -S \"mail.example.com\" -u \"example\" -p \"password\" -P \"1 (Highest)\" -t \"Example <example@example.com>\"\n\n'+

        "    Send e-mail digitally signed with an S/MIME Certificate\n"+
        f'    $ {sendmsg} -s \"Example\" -f \"Example <example@example.com>\" -S \"mail.example.com\" -u \"example\" -p \"password\" -C \"cert.p12\" -t \"Example <example@example.com>\"\n\n'+

        "    Send e-mail digitally signed with PGP/MIME\n"+
        f'    $ {sendmsg} -s \"Example\" -f \"Example <example@example.com>\" -S \"mail.example.com\" -u \"example\" -p \"password\" -k \"passphrase\" -t \"Example <example@example.com>\"'"\n")

def carriers():
    '''Print out common carriers a user could use to send a text message'''

    print("If you do not see your carrier, use the network your provider uses. For example, the carrier Tello uses Sprint.\n")
    format_attachment_output([
    ("\033[1mUS CARRIERS\033[0m", " ", " "),
    ("\033[1mMobile carrier\033[0m", "        \033[1mSMS gateway domain\033[0m", "                \033[1mMMS gateway domain\033[0m"),
    ("--------------------------", "------------------------","------------------------"),
    ("Alltel", "sms.alltelwireless.com", "mms.alltelwireless.com"),
    ("AT&T", "txt.att.net", "mms.att.net"),
    ("Boost Mobile", "sms.myboostmobile.com", "myboostmobile.com"),
    ("Cricket Wireless", "mms.cricketwireless.net", "mms.cricketwireless.net"),
    ("FirstNet", "txt.att.net", "mms.att.net"),
    ("Google Fi", "msg.fi.google.com", ""),
    ("MetroPCS", "mymetropcs.com", "mymetropcs.com"),
    ("Republic Wireless", "text.republicwireless.com", ""),
    ("Sprint", "messaging.sprintpcs.com", "pm.sprint.com"),
    ("T-Mobile", "tmomail.net", "tmomail.net"),
    ("U.S. Cellular", "email.uscc.net",	"'mms.uscc.net"),
    ("Verizon Wireless", "vtext.com", "vzwpix.com"),
    ("Virgin Mobile", "vmobl.com", "vmpix.com\n"),
    ("\033[1m(CANADIAN CARRIERS)\033[0m", "",""),
    ("\033[1mMobile carrier\033[0m", "        \033[1mSMS gateway domain\033[0m", "                \033[1mMMS gateway domain\033[0m"),
    ("--------------------------", "------------------------","------------------------"),
    ("Bell Canada", "txt.bell.ca", ""),
    ("Bell MTS", "text.mts.net", ""),
    ("Fido Solutions", "fido.ca",""),
    ("Freedom Mobile", "txt.freedommobile.ca", ""),
    ("Koodo Mobile", "msg.telus.com", ""),
    ("PC Mobile","mobiletxt.ca", ""),
    ("Rogers Comm", "pcs.rogers.com", ""),
    ("SaskTel", "sms.sasktel.com", ""),
    ("Telus", "msg.telus.com", "\n")])
