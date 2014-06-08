import os
import sys
import subprocess
import shutil

if os.environ['TRAVIS_PULL_REQUEST'] != "false":
    sys.exit(0)

if len(sys.argv) != 2:
    sys.exit(1)

built = sys.argv[1]

os.mkdir("out")
os.chdir("out")
subprocess.check_call(["git","init","."])
subprocess.check_call(["git","config","--global","user.email","ekr-cibot@rtfm.com"])
subprocess.check_call(["git","config","--global","user.name","EKR CI Bot"])
subprocess.check_call(["git","config","core.askpass","true"])
shutil.copy("../%s"%built, "index.html")
subprocess.check_call(["git","add", "index.html"])
subprocess.check_call(["git","commit","-m", "Commit"])
try:
    subprocess.check_output(["git","push","--force","https://%s@%s"%(os.environ['GH_TOKEN'],
                                                                     os.environ['GH_REF'])
                             ,"master:gh-pages","-q"],
                            stderr=subprocess.STDOUT,
                            stdin=subprocess.PIPE)
except:
    sys.stderr.write("Upload failed\n")
    sys.exit(1)
sys.exit(0)


