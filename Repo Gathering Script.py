import os
import shutil
import time
import json
from datetime import datetime
import urllib
import urllib.request

jsondata = []

url = 'https://api.github.com/search/repositories?q=created:2024-01-01&sort=stars&order=desc&page=1&per_page=100'
apiData = urllib.request.urlopen(url)



pwdStart = os.getcwd()
dumpDir = "Dump-" + str(datetime.now().time())

os.chdir(pwdStart)

data = json.load(apiData)

os.mkdir(dumpDir)
os.chdir(pwdStart + "/" + dumpDir)
pwd = os.getcwd()

#Parse through each object
for repo in data['items']:
    
    print("Repo: " + repo['name'])
    fullRepo = repo['html_url']
    repo = fullRepo.split('/')[-1]
    #clones the repo
    os.system("git clone --depth 1 " + fullRepo)
    #checks if the workflow folder exists
    GHexisting = os.path.exists(pwd + "/" + repo + '/.github/workflows')
    consolidatedExisting = os.path.exists(pwdStart + "/" + "consolidated")
    
    if consolidatedExisting == False:
        os.mkdir(pwdStart + "/" + "consolidated")

    #keeps folder if it exists
    if GHexisting == True:
        print("YAML folder exists")
        consolidated = pwdStart + "/" + "consolidated" + "/" + repo
        os.mkdir(consolidated)

        for file in os.listdir(pwd + "/" + repo + '/.github/workflows'):
            if file.endswith(".yml") or file.endswith(".yaml"):
                shutil.copy(pwd + "/" + repo + '/.github/workflows' + '/' + file, consolidated)
        shutil.rmtree(pwd + "/" + repo)

    #removes the directory if it doesn't have github actions yaml files
    else:
        shutil.rmtree(pwd + "/" + repo)



    print("============================")
    time.sleep(5)