# Python Port of Teal Dulcet's sendmsg.sh Script

## Libraries to use (Suggestion credit: Teal Dulcet)
[email](https://docs.python.org/3/library/email.html)
[smptlib](https://docs.python.org/3/library/smtplib.html) -- I like this especially

## Ways to Email Oneself

# With script

output=$(sudo python2 runMythNew.py 2>&1); ./send.sh "'$HOSTNAME' is done"'!' "Exit code: $?\nOutput:\n$output\n"
[comment]: # ( output=$(sudo python2 runMythNew.py 2>&1); ./send.sh "'$HOSTNAME' is done"'!' "Exit code: $?\nOutput:\n$output\n" )

# Without script 

output=$(sudo python2 runMythNew.py 2>&1); headers="From: Daniel Connelly <danc2@pdx.edu>\nTo: Daniel Connelly <5035044930@tmomail.net>\nSubject: =?utf-8?B?$(echo "'$HOSTNAME' is done"'!' | base64 -w 0)?=\nDate: $(date -R)\n"; message="Content-Type: text/plain; charset=utf-8\n\nExit code: $?\nOutput:\n$output\n"; echo -e "$headers$message" | curl -sS "smtps://smtp.gmail.com" --mail-from "danc2@pdx.edu" --mail-rcpt "5035044930@tmomail.net" -T - -u "danc2@pdx.edu:PASSWORD"


