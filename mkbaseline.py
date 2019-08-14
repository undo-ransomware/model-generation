#!/usr/bin/python3
import io
import os
import sys
import json
import magic
import requests
from math import log2
from magic import Magic
from ncmime import ncmime
from collections import Counter

ZEROS = Counter(range(256)) # ones, so never-seen bytes have defined entropy
def add(counter, key, counts):
	counter[key] = counter.get(key, ZEROS) + counts
def entropy(counter):
	return { mime: [-log2(counts[byte] / sum(counts.values()))
			for byte in range(256)] for mime, counts in counter.items() }

ncstats = dict()
magicstats = dict()
magyc = Magic(mime=True)
for dir in sys.argv[1:]:
	for file in os.listdir(dir):
		path = os.path.join(dir, file)
		with io.open(path, 'rb') as infile:
			counts = Counter(infile.read())
		add(ncstats, ncmime(path), counts)
		add(magicstats, magyc.from_file(path), counts)

def dump(basename, stats):
	with io.open(basename + '.json', 'w') as outfile:
		json.dump(entropy(stats), outfile, indent=4)

dump('ncbaseline', ncstats)
dump('magicbaseline', magicstats)
