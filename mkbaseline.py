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
from fileentropy import FileEntropy

db = sqlite3.connect('baselines.sqlite')
# order of index columns carefully chosen so the the two "group by" queries can
# directly do a linear scan of the table, without sorting.
db.execute('''create table if not exists counts(
		kind text, mime text, byte integer, path text, count integer,
		primary key(kind, mime, byte, path))''')

ZEROS = Counter()
def add(counter, key, counts):
	counter[key] = counter.get(key, ZEROS) + counts

def record(kind, path, stats):
	db.executemany('''insert into counts(kind, path, mime, byte, count)
			values(?, ?, ?, ?, ?)''', [(kind, path, mime, byte, count)
			for mime, counts in stats.items() for byte, count in counts.items()])

dirs = []
for dir in sys.argv[1:]:
	dirs.append(dir)

magyc = Magic(mime=True)
entroper = FileEntropy(1024)
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
		namestats = dict()
		for path in files:
			counts = Counter(entroper.count_bytes(path))
			add(ncstats, ncmime(path), counts)
			add(magicstats, magyc.from_file(path), counts)
			pathbytes = os.path.basename(path).encode('utf-8')
			add(namestats, 'filename', Counter(pathbytes))
		record('nc', dir, ncstats)
		record('magic', dir, magicstats)
		record('name', dir, namestats)
		db.commit()
	print(dir)

for kind in 'nc', 'magic', 'name':
	total = dict()
	for mime, count in db.execute('''select mime, sum(count) from counts
			where kind = ? group by mime''', [kind]):
		total[mime] = count

	entropies = dict()
	for mime, byte, count in db.execute('''select mime, byte, sum(count)
			from counts where kind = ? group by mime, byte''', [kind]):
		if mime not in entropies:
			entropies[mime] = [-log2(0.5 / total[mime]) for x in range(256)]
		# zeros should never have been inserted because Counter's don't return
		# elements with zero counts
		assert count > 0
		entropies[mime][byte] = -log2(count / total[mime])

	with io.open(kind + 'baseline.json', 'w') as outfile:
		json.dump(entropies, outfile, indent=4)
