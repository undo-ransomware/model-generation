#!/usr/bin/python3
import io
import sys
import json
import numpy as np

INFINITE_ENTROPY = 32

def stats(data, inkey, outprefix, outsuffix):
	seq = data[inkey]
	if len(seq) == 0:
		mean = INFINITE_ENTROPY
		stdev = INFINITE_ENTROPY
	elif len(seq) == 1:
		mean = seq[0]
		stdev = INFINITE_ENTROPY
	else:
		mean = np.mean(seq)
		stdev = np.std(seq)
	data[outprefix + 'mean' + outsuffix] = mean
	data[outprefix + 'stdev' + outsuffix] = stdev
	del data[inkey]

def simplify(path):
	with io.open(path, 'rb') as jsons:
		for line in jsons:
			data = json.loads(line)
			data['class'] = cls
			
			if data['size'] > 0:
				#ebbv = data['entropy_by_byte_value']
				#for i in range(256):
				#	data['entropy.byte_%02x' % i] = ebbv[i]
				stats(data, 'entropy_by_byte_value', 'entropy_', '.by_byte_value')
			else:
				# that's a bunch of infinities for an empty file. these infinities
				# would break the stats, so just replace them with "fairly high"
				# values.
				#for i in range(256):
				#	data['entropy.byte_%02x' % i] = INFINITE_ENTROPY
				data['entropy_mean.by_byte_value'] = INFINITE_ENTROPY
				data['entropy_stdev.by_byte_value'] = INFINITE_ENTROPY
				del data['entropy_by_byte_value']
			for kind in 'within_block', 'relative_to_file', 'relative_to_mime_byext', 'relative_to_mime_libmagic':
				stats(data, 'entropy_curve.' + kind, 'entropy_', '.' + kind)
			print(json.dumps(data))

if len(sys.argv) <= 1:
	sys.stderr.write('usage: python simplefeatures.py class file.jsons...\n')
	sys.exit(1)
cls = sys.argv[1]
for path in sys.argv[2:]:
	simplify(path)
