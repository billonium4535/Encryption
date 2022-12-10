import os
import random
import shutil

dir_name = 0

for i in range(15):
    dir_name = dir_name + 1
    path = ("F:/Programming Projects/encription/test/" + str(dir_name))
    if os.path.exists(path):
        shutil.rmtree(path)
    os.mkdir(path)
    for j in range(random.randint(1, 5)):
        file_name = random.randint(1, 1000)
        file = open((path + "/" + str(file_name) + ".txt"), "w")
        file.write(str(random.randint(1, 10000000)))
        file.close()
