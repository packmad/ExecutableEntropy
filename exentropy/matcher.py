import glob
import argparse
import os.path
import numpy as np

def produce_mappings(data_file, mapping_file, output_file='rank.txt', metric=''):
    '''
    Given a file with data, the mapping file, an output name, it ranks the features.
    If metric is given as list of names separated by commas, each feature is expanded.
    i.e. -m Min,Max,Avg,Med
    '''
    if not os.path.exists(data_file):
        print(data_file,' file not found!')
        return
    if not os.path.exists(mapping_file):
        print(mapping_file,' file not found!')
        return
    data, names = [], []
    with open(data_file) as f:
        for line in f:
            val = float(line.rstrip())
            data.append(val)
    if  metric is None:
        with open(mapping_file) as f:
            for line in f:
                name = line.split(' ')[1]
                val = name.rstrip()
                names.append(val)
    else:
        with open(mapping_file) as f:
            for line in f:
                name = line.split(' ')[1]
                val = name.rstrip()
                elements = metric.split(',')
                for m in elements:
                    names.append(val+' '+m)

    output = [ [d,n] for (d,n) in zip(data, names) ]
    output.sort(key=lambda x: abs(x[0]))
    np.savetxt(output_file, np.array(output)[::-1], fmt='%s %s')

parser = argparse.ArgumentParser(description='Mapping reconstruction and list ranking')
parser.add_argument('data_file', metavar = 'data file')
parser.add_argument('mapping_file', metavar = 'mapping file')
parser.add_argument('output_file', metavar = 'output file')
parser.add_argument('-m', '--metrics', dest='metrics', metavar='list of metrics')
args = parser.parse_args()

produce_mappings(args.data_file, args.mapping_file, output_file=args.output_file, metric=args.metrics)
