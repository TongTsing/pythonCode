import subprocess
import time

def getLogpath(modelpath):
        tmpFolder = subprocess.check_output("ls "+modelpath, shell=True).split()
        resPath = ''
        if tmpFolder:
                resPath = modelpath +"/" + tmpFolder[-1] + "/log/"
        return resPath

def getLogfiles(allFiles, folderList):
        for i in folderList:
                logFiles = subprocess.check_output("ls " + i , shell=True).split()
                for File in logFiles:
                        allFiles.append(i+File)
        print(allFiles)
        return 0


def cleanAllfiles():
        basePath = "/usr/local/easyops/pkg/conf/"
        tmpList = subprocess.check_output("ls "+basePath, shell=True).split()
        folderList =[]
        allfiles = []
        for i in tmpList:
                modelPath = basePath + i
                folderList.append(getLogpath(modelPath))
        getLogfiles(allfiles, folderList)
        #clear log
        for i in allfiles:
                print("clear log file:{i}".format(i=i))
                subprocess.check_output("echo > "+ i, shell=True)
        return folderList



def main():
        cleanAllfiles()

if __name__ == "__main__":
        main()