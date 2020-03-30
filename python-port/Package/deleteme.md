# Python Port of Teal Dulcet's sendmsg.sh Script

# Road Map

~1) Make basic PyPi installation to get the idea of how it will work~
 ~- follow these instructions: https://packaging.python.org/tutorials/packaging-projects/~
2 or 3) Setup text and email notification
 - follow these instructions: https://packaging.python.org/tutorials/packaging-projects/
4) add advanced functionality.
 - create a list of phone provider gateways to output to user.
 - add other more advanced script features.
 - compile to binary(?) and set a CLI command to the PATH variable so a 
   user can use a CMDLine shortcut.


## Libraries to use (Suggestion credit: Teal Dulcet)
[email](https://docs.python.org/3/library/email.html)
[smptlib](https://docs.python.org/3/library/smtplib.html)
[smime](https://pypi.org/project/smime/) -- get S/MIME encryption functionality. (alternatively [M2Crypto](https://tools.ietf.org/doc/python-m2crypto/howto.smime.html)).

## Ways to Email Oneself

# With script

output=$(sudo python2 runMythNew.py 2>&1); ./send.sh "'$HOSTNAME' is done"'!' "Exit code: $?\nOutput:\n$output\n"
[comment]: # ( output=$(sudo python2 runMythNew.py 2>&1); ./send.sh "'$HOSTNAME' is done"'!' "Exit code: $?\nOutput:\n$output\n" )

# Without script 

output=$(sudo python2 runMythNew.py 2>&1); headers="From: Daniel Connelly <danc2@pdx.edu>\nTo: Daniel Connelly <5035044930@tmomail.net>\nSubject: =?utf-8?B?$(echo "'$HOSTNAME' is done"'!' | base64 -w 0)?=\nDate: $(date -R)\n"; message="Content-Type: text/plain; charset=utf-8\n\nExit code: $?\nOutput:\n$output\n"; echo -e "$headers$message" | curl -sS "smtps://smtp.gmail.com" --mail-from "danc2@pdx.edu" --mail-rcpt "5035044930@tmomail.net" -T - -u "danc2@pdx.edu:PASSWORD"



# Replacing date -d command
"Regarding the date -d command, I think you want to replace it with this function: https://docs.python.org/3/library/datetime.html#datetime.datetime.strptime, although you probably will want to use it directly on the output from openssl above, so that you can remove all the date commands..."
