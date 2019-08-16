#!/usr/bin/python3
import io
import os
import sys
import json
from math import log2
from PIL import Image
from magic import Magic
from ncmime import ncmime
from collections import Counter
from fileentropy import FileEntropy

with io.open('ncbaseline.json', 'r') as infile:
	ncbaseline = json.load(infile)
with io.open('magicbaseline.json', 'r') as infile:
	magicbaseline = json.load(infile)
with io.open('namebaseline.json', 'r') as infile:
	namebaseline = json.load(infile)['filename']

class Baseline:
	def __init__(self, baselines):
		self.baselines = baselines

	def __getitem__(self, mime):
		# FIXME this should honor aliases, eg. docm == doc
		if mime in self.baselines:
			return self.baselines[mime]
		return self.baselines['application/octet-stream']

def entropy(epb, counts):
	return sum(epb[byte] * count for byte, count in counts.items()) / sum(counts.values())

ENTROPY_BLOCKSIZE = 1024
ZEROS = Counter(range(256)) # ones, so never-seen bytes have defined entropy
magyc = Magic(mime=True)
entroper = FileEntropy(1024, Baseline(ncbaseline), Baseline(magicbaseline))
def extract_features(path):
	feats = { 'path': path }

	extmime = ncmime(path)
	magicmime = magyc.from_file(path)
	feats['mime.byext'] = extmime
	feats['mime.libmagic'] = magicmime

	size = os.stat(path).st_size
	feats['size'] = size
	ebbv, ec_block, ec_file, ec_nc, ec_magic = entroper.calculate(path, size, ncmime, magicmime)
	feats['entropy_by_byte_value'] = ebbv
	feats['entropy_curve.within_block'] = ec_block
	feats['entropy_curve.relative_to_file'] = ec_file
	feats['entropy_curve.relative_to_mime_byext'] = ec_nc
	feats['entropy_curve.relative_to_mime_libmagic'] = ec_magic
	namecounts = Counter(os.path.basename(path).encode('utf-8'))
	feats['entropy_in_filename'] = entropy(namebaseline, namecounts)

	try:
		with io.open(path, 'rb') as infile:
			Image.open(infile)
		valid_image = True
	except Exception:
		valid_image = False
	feats['valid_image'] = valid_image
	json.dump(feats, sys.stdout)
	sys.stdout.write('\n')

def process(path):
	if os.path.isdir(path):
		for file in os.listdir(path):
			process(os.path.join(path, file))
	else:
		extract_features(path)

for path in sys.argv[1:]:
	process(path)
