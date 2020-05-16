# sendpy
--------
## Overview
sendpy is a command line email and text notification program that makes use
of external and local SMTP servers to send messages.

However, sendpy is much more than that. sendpy is rich in features and use cases. 
For example, using this program, one may:

* Attach files to a message
* Send unicode emojis in the Subject or Body of a message
* Digitally sign a message with S/MIME or PGP encryption
* Send a notification when a long running process (LRP) has finished execution
* Delay the sending of an email until a specific time
* And more!

Help for sending an e-mail and understanding this program can be found using `sendpy --help`, `sendpy --emails`, `sendpy --examples`, and `sendpy --gateways`.

## Quick Start in 4 Easy Steps

To expedite the ability for users to send a message, here is a quick setup and example:

1. Install using the install command listed in PyPi. Be sure to use pip3.

2. Set the default configuration file to store repetitive commands (e.g., username, password) with the command `sendpy --config`.

3. Enable lower security settings in your external email client, if necessary (ex. [Gmail](https://myaccount.google.com/lesssecureapps)).

4. Send a basic message `sendpy -s "Employment Opportunity" -t "connellyd2050@gmail.com" -m "Hello, Daniel,\n\n When is a good time to talk about an open position we have for you?"`.

## Dependencies
The following non-standard libraries are used in this program:
[email](https://docs.python.org/3/library/email.html)
[smptlib](https://docs.python.org/3/library/smtplib.html)
[OpenSSL](https://www.openssl.org/)
[GPG](https://gnupg.org/)

The first two libraries, `email` and `smtplib`, will be installed automatically alongside 
this program. The last two, `OpenSSL` and `GPG`, are installed on most Linux 
distrubtions by default and may easily be installed on Windows and macOS.
However, so long as a user is not signing emails (the `-k` and `-C` flags),
one may use this program without any additional installations on Windows or
macOS.

## Donate
[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=W465UGL4BDZUN&currency_code=USD&source=url)

Bitcoin Wallet: 3F8h722kLoBFo94mUmEpAMZBR2tTm7pUPs

Ether Wallet: 0x83AB7667A846eC26386Eedfa19E668eCE7E54120
