import os
import subprocess

print(os.path.exists("file.txt"))
print(os.system("trap rm \"file.txt\" EXIT"))
#print(os.system("trap rm 'file.txt' EXIT"))
print(os.path.exists("file.txt"))
