import argparse
import os
import sys
from __init__ import ElfInfo

parser = argparse.ArgumentParser(description='Extract imports from all ELF files in directory')
parser.add_argument('folder', metavar='dir', help='the folder to be analyzed')
parser.add_argument('output_file', metavar='file', help='where to write results')
args = parser.parse_args()
result_set = set()
DIR = args.folder
OUT_PATH = args.output_file
if not os.path.isdir(DIR):
    print(DIR + ' does not exists or it is not a folder.')
    sys.exit()

for dirpath, dir_names, file_names in os.walk(args.folder):
    for f in file_names:
        file_path = os.path.join(dirpath, f)
        try:
            elf = ElfInfo(open(file_path,'rb'))
            elf.get_infos()
            for i in elf.data['imports']:
                result_set.add(i)
        except Exception as e:
            print('Problem with file: ',file_path,'\nError is: ',e) 

f = open(OUT_PATH, 'w')
for i in result_set:
    f.write("{}\n".format(i))
f.close()
