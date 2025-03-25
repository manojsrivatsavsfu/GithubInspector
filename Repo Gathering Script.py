import os
import shutil
import time
import json
from datetime import datetime

jsondata = []

pwd = os.getcwd()
dumpDir = "Dump-" + str(datetime.now().time())

os.chdir(pwd)

#open JSON file from Github Search API
with open(pwd + '/repositories1.json', 'r') as file:
    data = json.load(file)

os.mkdir(dumpDir)
os.chdir(pwd + "/" + dumpDir)
pwd = os.getcwd()

#Parse through each object
for repo in data['items']:
    
    print("Repo: " + repo['name'])
    fullRepo = repo['html_url']
    repo = fullRepo.split('/')[-1]
    #clones the repo
    os.system("git clone --depth 1 " + fullRepo)
    #checks if the workflow folder exists
    existing = os.path.exists(pwd + "/" + repo + '/.github/workflows')
    #keeps folder if it exists
    if existing == True:
        print("YAML folder exists")
    #removes the directory if it doesn't
    else:
        shutil.rmtree(pwd + "/" + repo)

    print("============================")
    time.sleep(5)