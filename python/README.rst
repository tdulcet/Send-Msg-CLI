# sendpy
--------
## Overview
sendpy is a command line email and text notification program that makes use
of external and local SMTP servers to send messages.

However, sendpy is much more than that. sendpy is rich in features and use cases. 
For example, using this program, one may:

* Attach files to a message
* Send Unicode characters/emojis in the Subject or Body of a message
* Digitally sign a message with S/MIME or PGP encryption
* Send a notification when a long running process (LRP) has finished execution
* Delay the sending of an email until a specific time
* And more!

Help for sending an e-mail and understanding this program can be found using `sendpy --help`, `sendpy --examples`, `sendpy --smtp-servers`, and `sendpy --gateways`.

## Quick Start in 4 Easy Steps

To expedite the ability for users to send a message, here is a quick setup and example:

1. Install: `pip3 install sendpy` or `python3 -m pip install sendpy`.

2. Set the default configuration file to store repetitive commands (e.g., username, password): `sendpy --config`.

3. If necessary, create an App Password or enable less secure app access with your external email service (ex. [Gmail](https://myaccount.google.com/lesssecureapps)).

4. Send a basic message: `sendpy --subject "Employment Opportunity" --to "connellyd2050@gmail.com" --message "Hello,\n\n When is a good time to talk about an open position we have for you?"`.

## Dependencies
The following libraries are used in this program:
* [OpenSSL](https://www.openssl.org/)
* [GNU Privacy Guard](https://gnupg.org/) (GPG)

OpenSSL and GPG, are installed on most Linux 
distributions by default and may easily be installed on Windows and macOS.
However, so long as a user is not signing emails (the `--passphrase` and `--certificate` flags),
one may use this program without any additional installations on Windows or
macOS.

## Help
```
$ sendpy --help
usage:  [-h] [-v] [-s SUBJECT] [-m MESSAGE] [--message-file MESSAGE_FILE] [-a ATTACHMENTS] [-t TOEMAILS] [-c CCEMAILS] [-b BCCEMAILS] [-f FROMEMAIL] [-S SMTP] [--tls] [--starttls] [-u USERNAME]
        [-p PASSWORD] [-P {5 Lowest),4 (Low),Normal,2 (High),1 (Highest}] [-r] [-C CERT] [-k PASSPHRASE] [-z ZIPFILE] [-l] [-U] [-T TIME] [-d] [-n NOTIFY] [-V] [--config] [--examples]
        [--smtp-servers] [--gateways]

One or more To, CC or BCC e-mail addresses are required. Send text messages by using the mobile providers e-mail to SMS or MMS gateway (see the --gateways option). See examples with the --examples
option.

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -s SUBJECT, --subject SUBJECT
                        Subject. Escape sequences are expanded. Supports Unicode characters.
  -m MESSAGE, --message MESSAGE
                        Message body. Escape sequences are expanded. Supports Unicode characters.
  --message-file MESSAGE_FILE
                        Message body from a file or standard input if the filename is '-'.
  -a ATTACHMENTS, --attachment ATTACHMENTS
                        Attachment filename. Use multiple times for multiple attachments. Supports Unicode characters in filename.
  -t TOEMAILS, --to TOEMAILS
                        To e-mail address. Use multiple times for multiple To e-mail addresses.
  -c CCEMAILS, --cc CCEMAILS
                        CC e-mail address. Use multiple times for multiple CC e-mail addresses.
  -b BCCEMAILS, --bcc BCCEMAILS
                        BCC e-mail address. Use multiple times for multiple BCC e-mail addresses.
  -f FROMEMAIL, --from FROMEMAIL
                        From e-mail address
  -S SMTP, --smtp SMTP  SMTP server. Optionally include a port with the "hostname:port" syntax. Defaults to port 465 with --ssl/--tls and port 25 otherwise. Use "localhost" if running a mail
                        server on this device.
  --tls                 Use a secure connection with SSL/TLS (Secure Socket Layer/Transport Layer Security)
  --starttls            Upgrade to a secure connection with StartTLS
  -u USERNAME, --username USERNAME
                        SMTP server username
  -p PASSWORD, --password PASSWORD
                        SMTP server password. For security, use the --config option instead for it to prompt you for the password and then store in the configuration file.
  -P {5 (Lowest),4 (Low),Normal,2 (High),1 (Highest)}, --priority {5 (Lowest),4 (Low),Normal,2 (High),1 (Highest)}
                        Priority. Supported priorities: "5 (Lowest)", "4 (Low)", "Normal", "2 (High)" and "1 (Highest)"
  -r, --receipt         Request Return Receipt
  -C CERT, --certificate CERT
                        S/MIME Certificate filename for digitally signing the e-mails. It will ask you for the password the first time you run the script with this option.
  -k PASSPHRASE, --passphrase PASSPHRASE
                        PGP secret key passphrase for digitally signing the e-mails with PGP/MIME. For security, use 'config' for it to prompt you for the passphrase and then store in the
                        configuration file.
  -z ZIPFILE, --zip ZIPFILE
                        Compress attachment(s) with zip
  -l, --language        Set Content-Language. Uses value of LANG environment variable on Linux.
  -U, --sanitize-date   Uses Coordinated Universal Time (UTC) and rounds date down to whole minute.
  -T TIME, --time TIME  Time to delay sending of the e-mail
  -d, --dry-run         Dry run, do not send the e-mail
  -n NOTIFY, --notify NOTIFY
                        Run provided command and then send an e-mail with resulting output and exit code.
  -V, --verbose         Verbose, show the client-server communication
  --config              Store the --from, --smtp, --tls, --starttls, --username and --password option values in a '.sendpy.ini' configuration file as defaults for future use. It will prompt for
                        any values that are not provided.
  --examples            Show example usages of this script and exit
  --smtp-servers        Show a list of the SMTP servers for common e-mail services, then exit
  --gateways            Show a list the of SMS and MMS Gateways for common mobile providers in the United States and Canada, then exit
```

## Examples
```
$ sendpy --examples
Sendpy Examples (assumes config file is used):
    Send e-mail
    $ sendpy --subject "Example" --to "User <user@example.com>"

    Send e-mail with message
    $ sendpy --subject "Example" --message 'This is an example!' --to "User <user@example.com>"

    Send e-mail with message and single attachment
    $ sendpy --subject "Example" --message 'This is an example!' --attachment example.txt --to "User <user@example.com>"

    Send e-mail with message and multiple attachments
    $ sendpy --subject "Example" --message 'This is an example!' --attachment example1.txt --attachment example2.txt --to "User <user@example.com>"

    Send e-mail to a CC address
    $ sendpy --subject "Example" --to "User 1 <user1@example.com>" --cc "User 2 <user2@example.com>"

    Set config file with external SMTP server
    $ sendpy --from "Example <example@example.com>" --smtp "mail.example.com" --tls --username "example" --config

    Send high priority e-mail
    $ sendpy --subject "Example" --priority "1 (Highest)" --to "User <user@example.com>"

    Send e-mail digitally signed with an S/MIME Certificate
    $ sendpy --subject "Example" --certificate "cert.p12" --to "User <user@example.com>"

    Send e-mail digitally signed with PGP/MIME
    $ sendpy --subject "Example" --passphrase "config" --to "User <user@example.com>"

```

## Donate
[PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=NJ4PULABRVNCC)
