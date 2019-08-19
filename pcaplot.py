#!/usr/bin/python3
import io
import sys
import json
import numpy as np

def stats(data, inkey, outprefix, outsuffix):
	seq = data[inkey]
	data[outprefix + 'mean' + outsuffix] = np.mean(seq)
	data[outprefix + 'stdev' + outsuffix] = np.std(seq)
	del data[inkey]

def simplify(path):
	with io.open(path, 'rb') as jsons:
		for line in jsons:
			data = json.loads(line)
			data['class'] = cls
			
			ebbv = data['entropy_by_byte_value']
			for i in range(256):
				data['entropy.byte_%02x' % i] = ebbv[i]
			stats(data, 'entropy_by_byte_value', 'entropy_', '.by_byte_value')
			for kind in 'within_block', 'relative_to_file', 'relative_to_mime_byext', 'relative_to_mime_libmagic':
				stats(data, 'entropy_curve.' + kind, 'entropy_', '.' + kind)
			print(data)

if len(sys.argv) == 1:
	sys.stderr.write('usage: python pcaplot.py file.jsons...\n')
	sys.exit(1)

headers = None
with io.open('pcaplot.tmp', 'w') as dataset:
	for path in sys.argv[1:]:
		with io.open(path, 'rb') as jsons:
			for line in jsons:
				data = json.loads(line)
				del data['path']
				#data['class'] = 0
				#del data['mime.byext']
				for i in range(1, 255):
					del data['entropy.byte_%02x' % i]
				del data['mime.libmagic']
				data['valid_image'] = 1 if data['valid_image'] else 0
				if headers is None:
					headerSet = set(data.keys())
					headers = list(data.keys())
					dataset.write('%s\n' % '\t'.join(headers))
				elif headerSet != data.keys():
					print('mismatching fields:')
					print(headerSet)
					print(data.keys())
				dataset.write('%s\n' % '\t'.join(str(data[field]) for field in headers))
