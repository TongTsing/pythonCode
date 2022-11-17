import subprocess
shellResult = subprocess.check_output(cmd="dir C:\\", shell=True)
print(shellResult)