from itertools import starmap

"""Copyright © Daniel Connelly and Teal Dulcet.

Purpose: Deliver a variety of help commands to the user to explain usage of sendpy.
"""

# user codeskyblue from: https://stackoverflow.com/questions/19103052/python-string-formatting-columns-in-line


def format_attachment_output(rows):
    """Spaces the printing of attachments based on largest length. A replacement for the column cmd.
    Also used for printing out our help menus found in usage.py.
    """
    lens = [max(len(v) for v in col) for col in zip(*rows)]
    aformat = "  ".join(f"{{:<{alen}}}" for alen in lens)
    print("\n".join(starmap(aformat.format, rows)))


def examples(programname):
    """Print examples of how to use this program."""
    print(f"""Sendpy Examples (assumes config file is used):
    Send e-mail
    $ {programname} --subject "Example" --to "User <user@example.com>"

    Send e-mail with message
    $ {programname} --subject "Example" --message 'This is an example!' --to "User <user@example.com>"

    Send e-mail with message and single attachment
    $ {programname} --subject "Example" --message 'This is an example!' --attachment example.txt --to "User <user@example.com>"

    Send e-mail with message and multiple attachments
    $ {programname} --subject "Example" --message 'This is an example!' --attachment example1.txt --attachment example2.txt --to "User <user@example.com>"

    Send e-mail to a CC address
    $ {programname} --subject "Example" --to "User 1 <user1@example.com>" --cc "User 2 <user2@example.com>"

    Set config file with external SMTP server
    $ {programname} --from "Example <example@example.com>" --smtp "mail.example.com" --tls --username "example" --config

    Send high priority e-mail
    $ {programname} --subject "Example" --priority "1 (Highest)" --to "User <user@example.com>"

    Send e-mail digitally signed with an S/MIME Certificate
    $ {programname} --subject "Example" --certificate "cert.p12" --to "User <user@example.com>"

    Send e-mail digitally signed with PGP/MIME
    $ {programname} --subject "Example" --passphrase "config" --to "User <user@example.com>"
""")


def carriers():
    """Print out common carriers a user could use to send a text message."""
    print("SMS and MMS Gateway domains\nSource: https://en.wikipedia.org/wiki/SMS_gateway#Email_clients")
    print("Use the relevant SMS gateway to send text messages or the MMS gateway to send messages with attachments")

    print("\nUnited States Carriers\n")
    format_attachment_output([
        ("Mobile carrier", "SMS gateway domain", "MMS gateway domain"),
        ("", "", ""),
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
        ("U.S. Cellular", "email.uscc.net", "mms.uscc.net"),
        ("Verizon Wireless", "vtext.com", "vzwpix.com"),
        ("Virgin Mobile", "vmobl.com", "vmpix.com")])
    print("\nCanadian Carriers\n")
    format_attachment_output([
        ("Mobile carrier", "SMS gateway domain"),
        ("", ""),
        ("Bell Canada", "txt.bell.ca"),
        ("Bell MTS", "text.mts.net"),
        ("Fido Solutions", "fido.ca"),
        ("Freedom Mobile", "txt.freedommobile.ca"),
        ("Koodo Mobile", "msg.telus.com"),
        ("PC Mobile", "mobiletxt.ca"),
        ("Rogers Comm", "pcs.rogers.com"),
        ("SaskTel", "sms.sasktel.com"),
        ("Telus", "msg.telus.com")])


def servers():
    """Print out common emails and how to use the SMTP servers to send messages from.
    This information may be outdated. Information is gained from:
    https://www.arclab.com/en/kb/email/list-of-smtp-and-pop3-servers-mailserver-list.html.
    """
    print("SMTP Servers\nPort 465 typically means SSL/TLS, while Port 587 means StartTLS\n")
    format_attachment_output([
        ("Email Provider", "SMTP Server"),
        ("", ""),
        ("Gmail", "smtp.gmail.com:465"),
        ("Outlook", "smtp.live.com:465"),
        ("Office365", "smtp.office365.com:465"),
        ("Yahoo Mail", "smtp.mail.yahoo.com:465"),
        ("Yahoo UK", "smtp.mail.yahoo.co.uk:465"),
        ("AOL", "smtp.aol.com:587"),
        ("AT&T", "smtp.att.yahoo.com:587"),
        ("Hotmail", "smtp.live.com:465 "),
        ("Comcast", "smtp.comcast.net:587"),
        ("Verizon", "outgoing.verizon.net:587"),
        ("Mail.com", "smtp.mail.com:465")])
