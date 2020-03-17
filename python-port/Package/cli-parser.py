#!/usr/bin/env python3

import sys
import getopt
import datetime

'''The purpose of this file is to parse all flags given on the cmdline.
   Skipping to the bottom main function is where the control-flow begins.

'''
#TODO\s:
'''
1. Switch to argparse? Argparse enables the ability to output a specific help message
  rather than the entire help menu.
2. Create "long" options for options.
  Reminder: Update help menu and getopts (if long options are available)
3. Do we need the check that we are on linux now with this Python script version? Ask Teal.
'''

###Variables

# TODO -- I want to rework the way that I indicate an email is being sent... like an "(-e,--email)" flag?
'''
# Send e-mails
# Comment this out to temporally disable
SEND=1
'''

VARS={"TOEMAILS":[],"CCEMAILS":[],"BCCEMAILS":[],"FROMEMAIL":'',"SMTP":'',"USERNAME":'',"PASSWORD":'',"PRIORITY":"Normal","CERT":"cert.p12","CLIENTCERT":"cert.pem","PASSPHRASE":'',"WARNDAYS":"3","ZIPFILE":'',"VERBOSE":"1","NOW":datetime.datetime.now().strftime("%A, %B %d. %Y %I:%M%p"),"SUBJECT":'',"MESSAGE":'',"ATTACHMENTS":[]}

# TODO -- add these
'''
TOADDRESSES=( "${TOEMAILS[@]}" )
TONAMES=( "${TOEMAILS[@]}" )
CCADDRESSES=( "${CCEMAILS[@]}" )
CCNAMES=( "${CCEMAILS[@]}" )
BCCADDRESSES=( "${BCCEMAILS[@]}" )
FROMADDRESS=$FROMEMAIL
FROMNAME=$FROMEMAIL
'''

# Output usage
# usage <program name>
def usage():
    print("Usage:  $1 <OPTION(S)>... -s <subject>\n"+
    "or:     $1 <OPTION>\n"+
    "One or more To, CC or BCC e-mail addresses are required. Send text messages by using the mobile providers e-mail to SMS or MMS gateway (https://en.wikipedia.org/wiki/SMS_gateway#Email_clients). All the options can also be set by opening the script in an editor and setting the variables at the top. See examples below.\n"+

    "Options:\n"+
        "-s <subject>    Subject\n"+
                            "Escape sequences are expanded. Supports Unicode characters.\n"+
        "-m <message>    Message body\n"+
                            "Escape sequences are expanded. Supports Unicode characters.\n"+
        "-a <attachment> Attachment filename\n"+
                            "Use multiple times for multiple attachments. Supports Unicode characters in filename.\n"+
        "-t <To address> To e-mail address\n"+
                            "Use multiple times for multiple To e-mail addresses.\n"+
        "-c <CC address> CC e-mail address\n"+
                            "Use multiple times for multiple CC e-mail addresses.\n"+
        "-b <BCC address>BCC e-mail address\n"+
                            "Use multiple times for multiple BCC e-mail addresses.\n"+
        "-f <From address>From e-mail address\n"+

        "-S <SMTP server>SMTP server\n"+
                            "Supported protocols: \"smtp\" and \"smtps\". Requires From e-mail address. Use \"smtp://localhost\" if running a mail server on this device.\n"+
        "-u <username>   SMTP server username\n"+
        "-p <password>   SMTP server password\n"+
        "-P <priority>   Priority\n"+
                            "Supported priorities: \"5 (Lowest)\", \"4 (Low)\", \"Normal\", \"2 (High)\" and \"1 (Highest)\". Requires SMTP server.\n"+
        "-C <certificate>S/MIME Certificate filename for digitally signing the e-mails\n"+
                            "It will ask you for the password the first time you run the script with this option. Requires SMTP server.\n"+
        "-k <passphrase> PGP secret key passphrase for digitally signing the e-mails with PGP/MIME\n"+
                            "Requires SMTP server.\n"+
        "-z <zipfile>    Compress attachment(s) with zip\n"+
        "-d              Dry run, do not send the e-mail\n"+
        "-V              Verbose, show the client-server communication\n"+
                            "Requires SMTP server.\n"+

        "-h              Display this help and exit\n"+
        "-v              Output version information and exit\n"+

    "Examples:\n"+
        "Send e-mail\n"+
        "$ $1 -s \"Example\" -t \"Example <example@example.com>\"\n"+

        "Send e-mail with message\n"+
        "$ $1 -s \"Example\" -m \"This is an example"'!'"\" -t \"Example <example@example.com>\"\n"+

        "Send e-mail with message and single attachment\n"+
        "$ $1 -s \"Example\" -m \"This is an example"'!'"\" -a example.txt -t \"Example <example@example.com>\"\n"+

        "Send e-mail with message and multiple attachments\n"+
        "$ $1 -s \"Example\" -m \"This is an example"'!'"\" -a example1.txt -a example2.txt -t \"Example <example@example.com>\"\n"+

        "Send e-mail to a CC address\n"+
        "$ $1 -s \"Example\" -t \"Example 1 <example1@example.com>\" -c \"Example 2 <example2@example.com>\"\n"+

        "Send e-mail with a From address\n"+
        "$ $1 -s \"Example\" -f \"Example <example@example.com>\" -t \"Example <example@example.com>\"\n"+

        "Send e-mail with an external SMTP server\n"+
        "$ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -t \"Example <example@example.com>\"\n"+

        "Send high priority e-mail\n"+
        "$ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -P \"1 (Highest)\" -t \"Example <example@example.com>\"\n"+

        "Send e-mail digitally signed with an S/MIME Certificate\n"+
        "$ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -C \"cert.p12\" -t \"Example <example@example.com>\"\n"+

        "Send e-mail digitally signed with PGP/MIME"+ "$ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -k \"passphrase\" -t \"Example <example@example.com>\""+")\n")

def assign_variables(opt, arg):
    '''Find the correct variable to assign the opt to.
    '''
    # TODO -- finish where you left off...
    if opt in ("-a"):
        print("ENTERED")
        VARS["ATTACHMENTS"].append(arg)
        print(VARS["ATTACHMENTS"])

    '''
	;;
	b )
		BCCEMAILS+=( "$OPTARG" )
	;;
	c )
		CCEMAILS+=( "$OPTARG" )
	;;
	d )
		SEND=''
	;;
	f )
		FROMEMAIL=$OPTARG
	;;
	h )
		usage "$0"
		exit 0
	;;
	k )
		PASSPHRASE=$OPTARG
	;;
	m )
		MESSAGE=$OPTARG
	;;
	p )
		PASSWORD=$OPTARG
	;;
	s )
		SUBJECT=$OPTARG
	;;
	t )
		TOEMAILS+=( "$OPTARG" )
	;;
	u )
		USERNAME=$OPTARG
	;;
	v )
		echo -e "Send Msg CLI 1.0\n"
		exit 0
	;;
	z )
		ZIPFILE=$OPTARG
	;;
	C )
		CERT=$OPTARG
	;;
	P )
		PRIORITY=$OPTARG
	;;
	S )
		SMTP=$OPTARG
	;;
	V )
		VERBOSE=1
	;;
	\? )
    '''

def main(argv):
    try:
        #opts, args = getopt.getopt(argv,"hi:o:")
        opts, args = getopt.getopt(argv,"a:b:c:df:hk:m:p:s:t:u:vz:C:P:S:V")
    except getopt.GetoptError: # throws when flag is not in the set in the above line
        usage()
        sys.exit(2)

    print(opts, args)
    print(len(opts), len(args))
    # TODO
    '''
    1. get rid of function "assign_variables". We can do this because we either assign a string
       or append to a list if we find an opt on our command line.
       We must have the long flag version (e.g., -a => --attachments), and
       then we can say opt = opt[1:].upper() and then we can say:

        if opt in VARS:
            if type(VARS[opt]) is list(): # we have a list
                VARS[opt].append(arg)
        else: # we have a string
            VARS[opt]=arg

        # The only exceptions are verbose (set to 1) and version (echo), which you can program if cases for
        manually
    '''

    for opt, arg in opts:
        assign_variables(opt, arg)
        #print(opt, arg)

if __name__=="__main__":
    main(sys.argv[1:])

