#!/usr/bin/python3
import io
import sys
import json
import numpy as np

classes = None
features = None
byte_entropies = None
headers = None
infos = []
observations = 1000
non_numeric = ['path', 'mime.byext', 'mime.libmagic']

def resize(obs):
	global observations
	observations = obs
	features.resize(observations, len(headers))
	byte_entropies.resize(observations, 256)
	classes.resize(observations)

def check_fields(data):
	global headers, features, byte_entropies, classes

	fields = set(data.keys())
	for nn in non_numeric:
		fields.discard(nn)

	if headers is None:
		headers = list(fields)
		features = np.zeros((observations, len(headers)), dtype=np.float32)
		byte_entropies = np.zeros((observations, 256), dtype=np.float32)
		classes = np.zeros(observations, dtype=np.int8)
	elif set(headers) != fields:
		print(headers)
		print(data.keys())
		raise Exception('mismatching fields')

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

def simplify(data):
	for kind in ['within_block', 'relative_to_file', 'relative_to_mime_byext',
			'relative_to_mime_libmagic']:
		stats(data, 'entropy_curve.' + kind, 'entropy_', '.' + kind)

	if data['size'] == 0:
		# that's a bunch of infinities for an empty file. these infinities
		# would break the stats, so just replace them with "fairly high"
		# values.
		bytes = [INFINITE_ENTROPY for i in range(256)]
	else:
		bytes = data['entropy_by_byte_value']
	del data['entropy_by_byte_value']
	return bytes

INFINITE_ENTROPY = 24
def append(data, bytes, cls, index):
	if index >= observations:
		resize(2 * observations)
	for field in range(len(headers)):
		features[index][field] = data[headers[field]]
	for b in range(256):
		byte_entropies[index][b] = bytes[b]
	classes[index] = cls
	infos.append({ key: data[key] for key in non_numeric })

if len(sys.argv) <= 1:
	sys.stderr.write('usage: python simplefeatures.py class=file.jsons...\n')
	sys.exit(1)

index = 0
for spec in sys.argv[1:]:
	cls, path = spec.split('=', 1)
	cls = int(cls)
	with io.open(path, 'rb') as jsons:
		line = jsons.readline()
		data = json.loads(line)
		bytes = simplify(data)
		check_fields(data)
		append(data, bytes, cls, index)
		index += 1

		for line in jsons:
			data = json.loads(line)
			bytes = simplify(data)
			append(data, bytes, cls, index)
			index += 1
			if index % 1000 == 0:
				sys.stderr.write('\r%dk %s ' % (index / 1000, path))
				sys.stderr.flush()
	sys.stderr.write('\r%d %s \n' % (index, path))
resize(index)
np.savez_compressed('simplefeatures', features=features, classes=classes,
		byte_entropies=byte_entropies)
with io.open('simplefeatures.headers.json', 'w') as outfile:
	json.dump(headers, outfile)
with io.open('simplefeatures.info.json', 'w') as outfile:
	json.dump(infos, outfile)
