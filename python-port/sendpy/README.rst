sendpy
--------
# Libraries Used (Suggestion credit: Teal Dulcet)
[email](https://docs.python.org/3/library/email.html)
[smptlib](https://docs.python.org/3/library/smtplib.html)

## Ways to Email Oneself

# With script

output=$(sudo python3 program.py 2>&1); sendpy.py "'$HOSTNAME' is done"'!' "Exit code: $?\nOutput:\n$output\n"
[comment]: # ( output=$(sudo python2 runMythNew.py 2>&1); ./send.sh "'$HOSTNAME' is done"'!' "Exit code: $?\nOutput:\n$output\n" )

