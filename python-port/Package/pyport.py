# Command:
#output=$(sudo python2 runMythNew.py 2>&1); headers="From: Daniel Connelly <danc2@pdx.edu>\nTo: Daniel Connelly <5035044930@tmomail.net>\nSubject: =?utf-8?B?$(echo "'$HOSTNAME' is done"'!' | base64 -w 0)?=\nDate: $(date -R)\n"; message="Content-Type: text/plain; charset=utf-8\n\nExit code: $?\nOutput:\n$output\n"; echo -e "$headers$message" | curl -sS "smtps://smtp.gmail.com" --mail-from "danc2@pdx.edu" --mail-rcpt "5035044930@tmomail.net" -T - -u "danc2@pdx.edu:School21!"


# original cmdline:

## output=$(myLRP arg1 arg2... 2>&1); ./sendmsg.sh -s "“myLRP arg1 arg2...” has finished"'!' -m "The program “myLRP arg1 arg2...” has finished on “$HOSTNAME”"'!'"\nExit code: $?\nOutput:\n$output\n"

## Backing up a file

##./sendmsg.sh -s "Log file" -m "Please see the attached log file." -a status.logI

## Sending

# Contains: From, To, Subject, and Date (separated by \n)
HEADERS = "From: " FROM +

# Contains: Content-Type, Exit Code, and Output
MESSAGE = ""

# curl command comes last
cmd = "curl -sS \"smtps://smtp.gmail.com\" --mail-from \"danc2@pdx.edu\" --mail-rcpt \"5035044930@tmomail.net\" -T - -u \"danc2@pdx.edu:School21!\""


