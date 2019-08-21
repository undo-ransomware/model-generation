import io
import sys
import json
import numpy as np

blob = np.load('simplefeatures.npz')
classes = blob['classes']
features = blob['features']
byte_entropies = blob['byte_entropies']
with io.open('simplefeatures.headers.json', 'r') as infile:
	headers = json.load(infile)
#with io.open('simplefeatures.info.json', 'r') as infile:
#	infos = json.load(infile)

with io.open('pcaplot.tmp', 'w') as dataset:
	fields = ['class'] + headers + ['entropy.byte_%02x' % i for i in range(256)]
	dataset.write('%s\n' % '\t'.join(fields))
	for index in range(len(features)):
		fields = [classes[index]] + features[index].tolist() + byte_entropies[index].tolist()
		fields = ['%.5f' % x for x in fields]
		dataset.write('%s\n' % '\t'.join(fields))
