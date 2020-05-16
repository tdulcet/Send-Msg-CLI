import os

'''Copyright © Daniel Connelly

   Purpose: Deliver a variety of help commands to the user to explain usage of sendpy.
'''
bold = '\033[1m'
reset = '\033[0m'
# must hardcode or else will be path, which is not what we want.
prog_name = "sendpy"
os.system("")  # to print above ASCII lines on Windows

# user codeskyblue from: https://stackoverflow.com/questions/19103052/python-string-formatting-columns-in-line


def format_attachment_output(rows):
    '''Spaces the printing of attachments based on largest length. A replacement for the column cmd.
       Also used for printing out our help menus found in usage.py.
    '''
    lens = []
    for col in zip(*rows):
        lens.append(max([len(v) for v in col]))
    format = " ".join(["{:<" + str(l) + "}" for l in lens])
    for row in rows:
        print(format.format(*row).strip('\n'))


def usage():
    '''Print out help menu'''
    # Bottom three print statements have to be printed separately so as not to affect the ...
    print(f"Usage: {prog_name} <OPTION(S)>... -S <SMTP server> -t <To address> -f <From address> -u <username> -p <password>", "")
    print(f'or: {prog_name} <OPTION>')
    print(f"One or more 'To', 'CC' or 'BCC' e-mail addresses are required. Send text messages by using the mobile providers e-mail to SMS or MMS gateway (see the -g or --gateways option). See examples by using the -e or --examples option.", "\n")

    # Then we create a row and print it
    print("Options:\nMandatory arguments to long options are mandatory for short options too.", '')
    format_attachment_output([
        ("    -a, --attachment <attachment>", "Attachment filename"),
        (" ", "-Use multiple times for multiple attachments. Supports Unicode characters in filename"),
        ("    -b, --bcc <address>", "BCC e-mail address"),
        (" ", "-Use multiple times for multiple BCC addresses"),
        ("    -c, --cc <address>",  "CC e-mail address"),
        (" ", "-Use multiple times for multiple CC addresses"),
        ("    --config",  "Configure default SMTP server (-S), from (-f), username (-u), and password (-p). to include by default every time you run this script"),
        ("    -C, --certificate <file path>",
         "S/MIME Certificate filename for digitally signing the e-mails"),
        (" ", "-It will ask you for the password the first time you run the script with this option"),
        ("    -d, --dryrun", "Dry run, do not send the e-mail"),
        ("    -e, --examples", "Show example usages for this script"),
        ("    -f, --from <address>", "From e-mail address"),
        ("    -g, --gateways", "Displays a non-complete listing of SMS and MMS Gateways for the US and Canada, then exits"),
        ("    -h, --help", "Display this help and exit"),
        ("    -k, --passphrase <passphrase>",
         "PGP secret key passphrase for digitally signing the e-mails with PGP/MIME"),
        (" ", "-For security, use 'config' as the passphrase to use the configuration file. It will then prompt you for the passphrase"),
        ("    -l, --language", "Set Content-Language"),
        (" ", "-Uses value of LANG environment variable."),
        ("    -m, --message <message>", "Message body"),
        (" ", "-Escape sequences are expanded. Supports Unicode characters"),
        ("    --message-file <file path>",
         "Delivers a message from a file. Optionally, can take input from standard input by entering '-' as the argument"),
        ("    -n, --notify <command>",
         "Get notified when program ends and receive output."),
        ("    -p, --password <password>", "SMTP server password"),
        ("    -P, --priority <priority>", "Priority"),
        (" ", "-Supported priorities: '5 (Lowest)', '4 (Low)', 'Normal', '2 (High)' and '1 (Highest)'"),
        ("    -s, --subject <subject>", "Subject"),
        (" ", "-Escape sequences are expanded. Supports Unicode characters"),
        ("    --starttls", "For use when using a non-standard port and an SMTP server that supports the startTLS method"),
        ("    --smtpservers",
         "Lists common SMTP servers and ports to use in this script, then exits"),
        ("    -S, --smtp <server>", "SMTP server"),
        (" ", "-External SMTP server example: 'smtp.example.com:465'. Defaults to port 25 without a port number"),
        ("", "-Use 'localhost:25' if running a mail server on this device"),
        ("    -t, --to <address>", "To e-mail address"),
        (" ", "-Use multiple times for multiple TO addresses"),
        ("    --tls", "For use when using a non-standard port and an SMTP server that supports the TLS method"),
        ("    -T, --time <seconds>", "Time to delay the sending of email"),
        ("    -u, --username <username>", "SMTP server username"),
        ("    -v, --version", "Output version information and exit"),
        ("    -V, --verbose", "Verbose, show the client-server communication"),
        ("    -z, --zipfile <filename>", "Compress attachment(s) with zip\n")])


def examples():
    '''Print examples of how to use this program'''
    print("Sendpy Examples (assumes config file is used):\n" +
          "    Send e-mail\n" +
          f'    $ {prog_name} --subject \"Example\" --to \"Example <example@example.com>\"\n\n' +

          "    Send e-mail with message\n" +
          f'    $ {prog_name} --subject \"Example\" --message "This is an example!" --to \"Example <example@example.com>\"\n\n' +

          "    Send e-mail with message and single attachment\n" +
          f'    $ {prog_name} --subject \"Example\" --message "This is an example!" --attachment "example.txt" --to \"Example <example@example.com>\"\n\n' +

          "    Send e-mail with message and multiple attachments\n" +
          f'    $ {prog_name} --subject \"Example\" --message \"This is an example!\" --attachment "example1.txt" --attachment example2.txt --to \"Example <example@example.com>\"\n\n' +

          "    Send e-mail to a CC address\n" +
          f'    $ {prog_name} --subject \"Example\" --to \"Example 1 <example1@example.com>\" --cc \"Example 2 <example2@example.com>\"\n\n' +

          "    Send high priority e-mail\n" +
          f'    $ {prog_name} --subject \"Example\" --priority \"1 (Highest)\" --to \"Example <example@example.com>\"\n\n' +

          "    Send e-mail digitally signed with an S/MIME Certificate\n" +
          f'    $ {prog_name} --subject \"Example\" --certificate \"cert.p12\" --to \"Example <example@example.com>\"\n\n' +

          "    Send e-mail digitally signed with PGP/MIME\n" +
          f'    $ {prog_name} --subject \"Example\" --passphrase \"config\" --to \"Example <example@example.com>\"'"\n")


def carriers():
    '''Print out common carriers a user could use to send a text message
    '''
    print("If you do not see your carrier, use the network your provider uses. For example, the carrier Tello uses Sprint.\nSource: https://en.wikipedia.org/wiki/SMS_gateway#Email_clients\n")
    print("Use the relevant SMS gateway to send messages or use the MMS gateway to send messages with attachments\n")

    format_attachment_output([
        (bold + "US CARRIERS", " ", " "),
        (bold + "Mobile carrier", bold + "    SMS gateway domain",
         bold + "        MMS gateway domain"),
        (reset + "------------------", "    -------------------------",
         "    ------------------------"),
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
        ("U.S. Cellular", "email.uscc.net",	"mms.uscc.net"),
        ("Verizon Wireless", "vtext.com", "vzwpix.com"),
        ("Virgin Mobile", "vmobl.com", "vmpix.com\n"),
        (bold + "CANADIAN CARRIERS", "", ""),
        (bold + "Mobile carrier", bold + "    SMS gateway domain",
         bold + "        MMS gateway domain"),
        (reset + "------------------", "    -------------------------",
         "    ------------------------"),
        ("Bell Canada", "txt.bell.ca", ""),
        ("Bell MTS", "text.mts.net", ""),
        ("Fido Solutions", "fido.ca", ""),
        ("Freedom Mobile", "txt.freedommobile.ca", ""),
        ("Koodo Mobile", "msg.telus.com", ""),
        ("PC Mobile", "mobiletxt.ca", ""),
        ("Rogers Comm", "pcs.rogers.com", ""),
        ("SaskTel", "sms.sasktel.com", ""),
        ("Telus", "msg.telus.com", "\n")])


def servers():
    '''Print out common emails and how to use the SMTP servers to send messages from.
       This information may be outdated. Information is gained from:
       https://www.arclab.com/en/kb/email/list-of-smtp-and-pop3-servers-mailserver-list.html
    '''
    print(bold + "Popular SMTP Servers and Corresponding Ports List\n")
    print(bold + "Email Provider\t", bold + "SMTP Server Example"+reset)
    print("--------------", "  -------------------------")
    format_attachment_output([
        ("Gmail", "\t smtp.gmail.com:465"),
        ("Outlook", "\t smtp.live.com:465"),
        ("Office365", "\t smtp.office365.com:465"),
        ("Yahoo Mail", "\t smtp.mail.yahoo.com:465"),
        ("Yahoo UK", "\t smtp.mail.yahoo.co.uk:465"),
        ("AOL", "\t smtp.aol.com:587"),
        ("AT&T", "\t smtp.att.yahoo.com:587"),
        ("Hotmail", "\t smtp.live.com:465 "),
        ("Comcast", "\t smtp.comcast.net:587"),
        ("Verizon", "\t outgoing.verizon.net:587"),
        ("Mail.com", "\t smtp.mail.com:465\n")])
