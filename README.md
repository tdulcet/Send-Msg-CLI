# Send Msg CLI
Linux Send E-mail Script

Copyright © 2019 Teal Dulcet (Bash) and Daniel Connelly (Python)

Send [e-mail](https://en.wikipedia.org/wiki/Email) (and [text messages](https://en.wikipedia.org/wiki/SMS)), with optional message and attachments, from the command line. Supports [Unicode characters](https://en.wikipedia.org/wiki/Unicode_and_email) in subject, message and attachment filename ([MIME](https://en.wikipedia.org/wiki/MIME)). Optionally use your own e-mail address and an external [SMTP](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol) server.

Useful to know when a cron job failed, when a long running job (LRP) has finished, to quickly backup/share a file or to send notifications as part of a larger script.

## Usage

Requires the curl and netcat commands, which are included on most Linux distributions.

Optional [S/MIME](https://en.wikipedia.org/wiki/S/MIME) digital signatures require the openssl command.\
Optional [PGP/MIME](https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP) digital signatures require the gpg command.

Run: `./sendmsg.sh <OPTION(S)>... -s <subject>`\
One or more To, CC or BCC e-mail addresses are required. Send text messages by using the mobile providers [e-mail to SMS or MMS gateway](https://en.wikipedia.org/wiki/SMS_gateway#Email_clients). All the options can also be set by opening the script in an editor and setting the variables at the top. See [Help](#help) below for full usage information.

1. Make sure the required commands above are installed.
2. Download the script ([sendmsg.sh](sendmsg.sh)). Run: `wget https://raw.github.com/tdulcet/Send-Msg-CLI/master/sendmsg.sh`.
3. At a minimum, you need to provide one To e-mail address. If the computer is on a residential network or if it does not have an SMTP server setup then you will also need to provide an external SMTP server. For security, any passwords/passphrases should be set in the script, instead of on the command line.
4. Execute the script once to make sure there are no errors. For example, run: `chmod u+x sendmsg.sh` and `./sendmsg.sh -s "Test" -m "This is a test!" -t "Example <example@example.com>" -d`.
5. If you want the script to be available for all users, install it. Run: `sudo mv sendmsg.sh /usr/local/bin/sendmsg` and `sudo chmod +x /usr/local/bin/sendmsg`.

### Examples

See [Help](#help) below for more examples.

Send a notification when a long running job (LRP) has finished, with the exit code and output:
```bash
output=$(myLRP arg1 arg2... 2>&1); ./sendmsg.sh -s "“myLRP arg1 arg2...” has finished"'!' -m "The program “myLRP arg1 arg2...” has finished on “$HOSTNAME”"'!'"\nExit code: $?\nOutput:\n$output\n"
```
Replace `myLRP arg1 arg2...` with the actual program and arguments.

Backup/Share a file:
```bash
./sendmsg.sh -s "Log file" -m "Please see the attached log file." -a status.log
```

Send notifications as part of a larger script:
```bash
./sendmsg.sh -s "⬇️ Example Website is DOWN"'!' -m "Example Website (https://www.example.com/) is currently DOWN"'!'"\n\nThis script will alert you when it is back up.\n"
```
Example adapted from the [Linux Remote Servers Status Monitoring Script](https://github.com/tdulcet/Remote-Servers-Status).

### Gmail

<details>
  <summary>Instructions</summary>

To send e-mail from a Gmail account, add these options to the command: `-f "Example <example@gmail.com>" -S "smtps://smtp.gmail.com" -u "example@gmail.com" -p "PASSWORD"`. Or, open the script in an editor and set these variables near the top, where listed:
```bash
FROMEMAIL="Example <example@gmail.com>"

SMTP="smtps://smtp.gmail.com"
USERNAME="example@gmail.com"
PASSWORD="PASSWORD"
```
Replace `example` with the username and `PASSWORD` with the actual password. For security, the password should be set in the script, instead of on the command line.

You will also need to enable "Less secure app access": https://myaccount.google.com/lesssecureapps. It is not actually less secure, since it is using the same SSL/TLS encryption (note the `smtps://` protocol). Note that Google may disable this setting if it is not being used. If you get a "Login denied" error, try visiting this page: https://accounts.google.com/DisplayUnlockCaptcha.
</details>

## Feature comparison

<table>
  <tr>
    <th></th>
    <th></th>
    <th>This Send E-mail Script</th>
    <th>S-nail (formerly Heirloom mailx)</th>
    <th>Mutt</th>
    <th>SSMTP</th>
    <th>SendEmail</th>
    <th>eMail</th>
    <th>smtp-cli</th>
  </tr>
  <tr>
    <th colspan="2">Send e-mail</th>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
  </tr>
  <tr>
    <th colspan="2">Send text messages (e-mail to SMS)</th>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
  </tr>
  <tr>
    <th colspan="2">Use your own e-mail address</th>
    <td>✔*</td>
    <td>✔*</td>
    <td>✔*</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
  </tr>
  <tr>
    <th colspan="2">Use an external SMTP server</th>
    <td>✔*</td>
    <td>✔*</td>
    <td>✔*</td>
    <td>✔</td>
    <td>✔*</td>
    <td>✔*</td>
    <td>✔*</td>
  </tr>
  <tr>
    <th colspan="2">Include attachment(s)</th>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td></td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
  </tr>
  <tr>
    <th colspan="2">Send e-mails to CC and BCC addresses</th>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <th colspan="2">Supports e-mail addresses with display names</th>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td></td>
    <td>✔</td>
    <td></td>
    <td>✔</td>
  </tr>
  <tr>
    <th colspan="2">Supports HTML formatted messages</th>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td>✔</td>
    <td></td>
    <td>✔</td>
  </tr>
  <tr>
    <th colspan="2">Supports Unicode characters in subject and message (MIME)</th>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td></td>
    <td>✔</td>
    <td>✔</td>
    <td>Message only</td>
  </tr>
  <tr>
    <th colspan="2">Supports International email addresses</th>
    <td>✔^</td>
    <td>✔</td>
    <td>✔</td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <th colspan="2">Supports E-mail Priority</th>
    <td>✔</td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td>High Priority only</td>
    <td></td>
  </tr>
  <tr>
    <th rowspan="2">Digitally sign the e-mails</th>
    <td>S/MIME certificate</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>PGP/MIME</td>
    <td>✔</td>
    <td></td>
    <td>✔</td>
    <td></td>
    <td></td>
    <td>✔</td>
    <td></td>
  </tr>
  <tr>
    <th colspan="2">Does NOT require compiling or installing anything</th>
    <td>✔</td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <th colspan="2">100% Open Source</th>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
    <td>✔</td>
  </tr>
  <tr>
    <th colspan="2">Free</th>
    <td>🆓</td>
    <td>🆓</td>
    <td>🆓</td>
    <td>🆓</td>
    <td>🆓</td>
    <td>🆓</td>
    <td>🆓</td>
  </tr>
</table>

\* Optional\
^ Only supported in Internationalizing Domain Names in Applications (IDNA) encoding\
^^ Does not work with all mobile providers

This is not a comprehensive list of the Send E-mail Script’s functionality.

Source: [S-nail](https://www.sdaoden.eu/code.html), [Mutt](http://www.mutt.org/), [SSMTP](https://packages.qa.debian.org/s/ssmtp.html), [SendEmail](https://web.archive.org/web/20191207001015/http://www.caspian.dotconf.net/menu/Software/SendEmail/) (archived, [source](https://github.com/mogaal/sendemail)), [eMail](https://github.com/deanproxy/eMail) and [smtp-cli](https://github.com/mludvig/smtp-cli)

## Help

```
$ sendmsg -h
Usage:  sendmsg <OPTION(S)>... -s <subject>
or:     sendmsg <OPTION>
One or more To, CC or BCC e-mail addresses are required. Send text messages by using the mobile providers e-mail to SMS or MMS gateway (https://en.wikipedia.org/wiki/SMS_gateway#Email_clients). All the options can also be set by opening the script in an editor and setting the variables at the top. See examples below.

Options:
    -s <subject>    Subject
                        Escape sequences are expanded. Supports Unicode characters.
    -m <message>    Message body
                        Escape sequences are expanded. Supports Unicode characters.
    -a <attachment> Attachment filename
                        Use multiple times for multiple attachments. Supports Unicode characters in filename.
    -t <To address> To e-mail address
                        Use multiple times for multiple To e-mail addresses.
    -c <CC address> CC e-mail address
                        Use multiple times for multiple CC e-mail addresses.
    -b <BCC address>BCC e-mail address
                        Use multiple times for multiple BCC e-mail addresses.
    -f <From address>From e-mail address

    -S <SMTP server>SMTP server
                        Supported protocols: "smtp" and "smtps". Requires From e-mail address. Use "smtp://localhost" if running a mail server on this device.
    -u <username>   SMTP server username
    -p <password>   SMTP server password
    -P <priority>   Priority
                        Supported priorities: "5 (Lowest)", "4 (Low)", "Normal", "2 (High)" and "1 (Highest)". Requires SMTP server.
    -C <certificate>S/MIME Certificate filename for digitally signing the e-mails
                        It will ask you for the password the first time you run the script with this option. Requires SMTP server.
    -k <passphrase> PGP secret key passphrase for digitally signing the e-mails with PGP/MIME
                        Requires SMTP server.
    -z <zipfile>    Compress attachment(s) with zip
    -l              Set Content-Language
                        Uses value of LANG environment variable.
    -U              Sanitize the Date
                        Uses Coordinated Universal Time (UTC) and rounds date down to whole minute. Set the TZ environment variable to change time zone.
    -d              Dry run, do not send the e-mail
    -V              Verbose, show the client-server communication
                        Requires SMTP server.

    -h              Display this help and exit
    -v              Output version information and exit

Examples:
    Send e-mail
    $ sendmsg -s "Example" -t "Example <example@example.com>"

    Send e-mail with message
    $ sendmsg -s "Example" -m "This is an example!" -t "Example <example@example.com>"

    Send e-mail with message and single attachment
    $ sendmsg -s "Example" -m "This is an example!" -a example.txt -t "Example <example@example.com>"

    Send e-mail with message and multiple attachments
    $ sendmsg -s "Example" -m "This is an example!" -a example1.txt -a example2.txt -t "Example <example@example.com>"

    Send e-mail to a CC address
    $ sendmsg -s "Example" -t "Example 1 <example1@example.com>" -c "Example 2 <example2@example.com>"

    Send e-mail with a From address
    $ sendmsg -s "Example" -f "Example <example@example.com>" -t "Example <example@example.com>"

    Send e-mail with an external SMTP server
    $ sendmsg -s "Example" -f "Example <example@example.com>" -S "smtps://mail.example.com" -u "example" -p "password" -t "Example <example@example.com>"

    Send high priority e-mail
    $ sendmsg -s "Example" -f "Example <example@example.com>" -S "smtps://mail.example.com" -u "example" -p "password" -P "1 (Highest)" -t "Example <example@example.com>"

    Send e-mail digitally signed with an S/MIME Certificate
    $ sendmsg -s "Example" -f "Example <example@example.com>" -S "smtps://mail.example.com" -u "example" -p "password" -C "cert.p12" -t "Example <example@example.com>"

    Send e-mail digitally signed with PGP/MIME
    $ sendmsg -s "Example" -f "Example <example@example.com>" -S "smtps://mail.example.com" -u "example" -p "password" -k "passphrase" -t "Example <example@example.com>"

```

## Scripts where this is incorporated

* [Linux Remote Servers Status Monitoring Script](https://github.com/tdulcet/Remote-Servers-Status)

## Contributing

Pull requests welcome! Ideas for contributions:

* Improve the performance
* Send e-mails with very long subjects or many e-mail addresses
* Support HTML formatted messages
* Support [International email](https://en.wikipedia.org/wiki/International_email) addresses
	* Currently they are only supported in Internationalizing Domain Names in Applications (IDNA) encoding.
* Provide an option to automatically upload large files to an external storage service, such as [Firefox Send](https://send.firefox.com) or [transfer.sh](https://transfer.sh)
* Support inputting the message body from standard input (stdin)
* Add tests
* Automatically renew the S/MIME certificate, as [certbot](https://certbot.eff.org/) does for [Let's Encrypt](https://letsencrypt.org/) certificates
* Port to Python (suggested by Daniel Connelly)

Thanks to [Daniel Connelly](https://github.com/Danc2050) for helping create the Feature comparison and test the script!
