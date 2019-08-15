#!/usr/bin/python3
import io
import os
import sys
import json
from math import log2
from magic import Magic
from ncmime import ncmime
from collections import Counter

with io.open('ncbaseline.json', 'r') as infile:
	ncbaseline = json.load(infile)
with io.open('magicbaseline.json', 'r') as infile:
	magicbaseline = json.load(infile)
with io.open('namebaseline.json', 'r') as infile:
	namebaseline = json.load(infile)['filename']

def getbaseline(baselines, mime):
	# FIXME this should honor aliases, eg. docm == doc
	if mime in baselines:
		return baselines[mime]
	return baselines['application/octet-stream']

def bytecounts(path):
	with io.open(path, 'rb') as infile:
		while True:
			block = infile.read(ENTROPY_BLOCKSIZE)
			if len(block) == 0:
				return
			yield Counter(block)

def entropy(epb, counts):
	return sum(epb[byte] * count for byte, count in counts.items()) / sum(counts.values())

ENTROPY_BLOCKSIZE = 1024
ZEROS = Counter(range(256)) # ones, so never-seen bytes have defined entropy
magyc = Magic(mime=True)
def extract_features(path):
	feats = { 'path': path }

	extmime = ncmime(path)
	magicmime = magyc.from_file(path)
	feats['mime.byext'] = extmime
	feats['mime.libmagic'] = magicmime
	epb_nc = getbaseline(ncbaseline, extmime)
	epb_magic = getbaseline(magicbaseline, magicmime)

	counts = ZEROS
	for block in bytecounts(path):
		counts += block
	nbytes = sum(counts.values())
	epb_file = [-log2(counts[byte] / nbytes) for byte in range(256)]
	feats['size'] = nbytes
	feats['entropy_per_byte'] = epb_file

	intseq = []
	extseq = []
	ncseq = []
	magicseq = []
	for block in bytecounts(path):
		total = sum(block.values())
		intseq.append(sum(-log2(c / total) * c for c in block.values()) / total)
		extseq.append(entropy(epb_file, block))
		ncseq.append(entropy(epb_nc, block))
		magicseq.append(entropy(epb_magic, block))
	feats['entropy_curve.within_block'] = intseq
	feats['entropy_curve.relative_to_file'] = extseq
	feats['entropy_curve.relative_to_mime_byext'] = ncseq
	feats['entropy_curve.relative_to_mime_libmagic'] = magicseq
	
	namecounts = Counter(os.path.basename(path).encode('utf-8'))
	feats['entropy_in_filename'] = entropy(namebaseline, namecounts)
	json.dump(feats, sys.stdout)

def process(path):
	if os.path.isdir(path):
		for file in os.listdir(path):
			process(os.path.join(path, file))
	else:
		extract_features(path)

for path in sys.argv[1:]:
	process(path)
