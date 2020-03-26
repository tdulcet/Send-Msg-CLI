import sys
import os

sys.path.append(os.environ["PWD"]) # allows "from" to be used (FIXME and the path of this module permanently to the environment so Python can search there and not have this line here
from configuration import Config
# TODO Add logic here for default configuration.

if __name__=='__main__':
    # program input
    config = Config()

    # program navigation
    while 1:
        num = config.menu()
        if num == 1:
            config.config_email()
        elif num == 2:
            config.config_text()
        elif num == 3:
            config.send_mail() # TODO -- do something with return values, or just send the message
        elif num == 4:
            config.send_text() # TODO -- do something with return values, or just send the text
        elif num == 5:
            config.sys.exit(0)
