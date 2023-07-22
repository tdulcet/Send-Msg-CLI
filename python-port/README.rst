# sendpy
--------
## Overview
sendpy is a command line email and text notification program that makes use
of external and local SMTP servers to send messages.

However, sendpy is much more than that. sendpy is rich in features and use cases. 
For example, using this program, one may:

* Attach files to a message
* Send Unicode emojis in the Subject or Body of a message
* Digitally sign a message with S/MIME or PGP encryption
* Send a notification when a long running process (LRP) has finished execution
* Delay the sending of an email until a specific time
* And more!

Help for sending an e-mail and understanding this program can be found using `sendpy --help`, `sendpy --examples`, `sendpy --smtp-servers`, and `sendpy --gateways`.

## Quick Start in 4 Easy Steps

To expedite the ability for users to send a message, here is a quick setup and example:

1. Install using the install command listed in PyPi. Be sure to use pip3.

2. Set the default configuration file to store repetitive commands (e.g., username, password) with the command `sendpy --config`.

3. Enable lower security settings in your external email client, if necessary (ex. [Gmail](https://myaccount.google.com/lesssecureapps)).

4. Send a basic message `sendpy --subject "Employment Opportunity" --to "connellyd2050@gmail.com" --message "Hello,\n\n When is a good time to talk about an open position we have for you?"`.

## Dependencies
The following libraries are used in this program:
* [OpenSSL](https://www.openssl.org/)
* [GNU Privacy Guard](https://gnupg.org/) (GPG)

OpenSSL and GPG, are installed on most Linux 
distributions by default and may easily be installed on Windows and macOS.
However, so long as a user is not signing emails (the `--passphrase` and `--certificate` flags),
one may use this program without any additional installations on Windows or
macOS.

## Donate
[PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=NJ4PULABRVNCC)