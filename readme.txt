#-------- Requirements --------#

Python 3.x
Python3's tkinter module
    'sudo apt-get install python3-tk' - on Debian/Ubuntu

python packages listed in included requirements.txt file
    'sudo pip3 install -r /path/to/requirements.txt'
    if pip3 is not available, it can be installed with:
    'sudo apt-get install python3-pip'

#-------- Running --------#

use your python3 interpreter to run the main.py file
 e.g. '/usr/bin/python3 /path/to/project/main.py'

in order to use file encryption/decryption, a remote device needs to be accessible via SSH;
    this will most likely require the exchange of ssh keys with the device (first manual login via 'ssh $user@$host')
    additionally, a directory named 'not_keys' should be created in the user's $HOME directory