import os
import shutil
import time
import json
from datetime import datetime

jsondata = []

pwd = os.getcwd()
dumpDir = "Dump-" + str(datetime.now().time())

os.chdir(pwd)

with open(pwd + '/repositories1.json', 'r') as file:
    data = json.load(file)

os.mkdir(dumpDir)
os.chdir(pwd + "/" + dumpDir)
pwd = os.getcwd()


for repo in data['items']:
    
    print("Repo: " + repo['name'])
    fullRepo = repo['html_url']
    repo = fullRepo.split('/')[-1]
    os.system("git clone --depth 1 " + fullRepo)
    existing = os.path.exists(pwd + "/" + repo + '/.github/workflows')

    if existing == True:
        print("YAML folder exists")
        
    else:
        shutil.rmtree(pwd + "/" + repo)

    print("============================")
    time.sleep(5)