#!/usr/bin/python3
import io
import os
import sys
import json
import magic
import sqlite3
import requests
from math import log2
from magic import Magic
from ncmime import ncmime
from collections import Counter

db = sqlite3.connect('baselines.sqlite')
db.execute('create table if not exists counts' +
		'(type next, path text, mime text, byte integer, count integer)')

ZEROS = Counter(range(256)) # ones, so never-seen bytes have defined entropy
def add(counter, key, counts):
	counter[key] = counter.get(key, ZEROS) + counts

def record(type, path, stats):
	db.executemany('''insert into counts(type, path, mime, byte, count)
			values(?, ?, ?, ?, ?)''', [(type, path, mime, byte, count)
			for mime, counts in stats.items() for byte, count in counts.items()])
	db.commit()

dirs = []
for dir in sys.argv[1:]:
	dirs.append(dir)

magyc = Magic(mime=True)
while len(dirs) > 0:
	dir = dirs.pop()
	files = []
	for file in os.listdir(dir):
		path = os.path.join(dir, file)
		if os.path.isdir(path):
			dirs.append(path)
		else:
			files.append(path)

	if db.execute('select count(*) from counts where path = ?',
			[dir]).fetchone()[0] == 0:
		ncstats = dict()
		magicstats = dict()
		for path in files:
			with io.open(path, 'rb') as infile:
				counts = Counter(infile.read())
			add(ncstats, ncmime(path), counts)
			add(magicstats, magyc.from_file(path), counts)
		record('nc', dir, ncstats)
		record('magic', dir, magicstats)
		print(dir)

def dump(type):
	total = dict()
	for mime, count in db.execute('''select mime, sum(count) from counts
			where type = ? group by mime''', [type]):
		total[mime] = count

	entropies = dict()
	for mime, byte, count in db.execute('''select mime, byte, sum(count)
			from counts where type = ? group by mime, byte''', [type]):
		if mime not in entropies:
			entropies[mime] = [0 for x in range(256)]
		entropies[mime][byte] = -log2(count / total[mime])

	with io.open(type + 'baseline.json', 'w') as outfile:
		json.dump(entropies, outfile, indent=4)

dump('nc')
dump('magic')
