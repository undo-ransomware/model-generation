import io
import os
import sys
import json
from numpy import mean
from stats import Stats
from math import sqrt, nan, inf
from collections import defaultdict, Counter

if len(sys.argv) < 3:
	sys.stderr.write('usage: python meta.py path/to/fileops/dump task-id...\n')
	sys.exit(1)
indir = sys.argv[1]
tasks = sys.argv[2:]

def append_warnings(tgt, src, fileinfo):
	normpath = fileinfo['filepath'].lower()
	if normpath in src:
		for code, msg in src[normpath].items():
			tgt.append(msg)

for task in tasks:
	taskdir = os.path.join(indir, task)
	fileops = dict()
	warnings = dict()
	with io.open(os.path.join(taskdir, 'fileops.json'), 'r') as fd:
		for line in fd:
			data = json.loads(line)
			fileops[data['filepath'].lower()] = data
	with io.open(os.path.join(taskdir, 'warnings.json'), 'r') as fd:
		for line in fd:
			data = json.loads(line)
			path = data['path']
			del data['path']
			warnings[path] = data

	ops = list()

	# tracked renames, ie. where we have fileops showing the rename.
	# create a copy of the list so we can delete items from the original set
	tracked = [(data['filepath'].lower(), data['original_filename'].lower())
			for data in fileops.values() if data['original_filename'] is not None]
	for tgt, src in tracked:
		source = fileops[src]
		target = fileops[tgt]
		if target['traceable_filename'] is None:
			ops.append(('modify_rename', source, target, []))
		else:
			warn = []
			if target['traceable_filename'].lower() != src:
				warn.append('target name traces to %s instead'
						% target['traceable_filename'])
			ops.append(('modify_addext', source, target, warn))
		del fileops[src]
		del fileops[tgt]

	# untracked renames we can infer by the sample using derived names
	untracked = [(data['filepath'].lower(), data['traceable_filename'].lower())
			for data in fileops.values() if data['traceable_filename'] is not None]
	for tgt, src in untracked:
		warn = []
		source = fileops[src]
		target = fileops[tgt]
		# TODO flag untracked if phantom_modify and phantom_deletion
		ops.append(('modify_addext', source, target, []))
		del fileops[src]
		del fileops[tgt]

	for single in fileops.values():
		warn = []
		if single['file_group'] in ('existing', 'phantom') and single['status'] == 'modified':
			ops.append(('modify', single, single, []))
		elif single['file_group'] in ('existing', 'phantom') and single['status'] == 'deleted':
			ops.append(('delete', single, None, []))
		elif single['file_group'] in ('existing', 'phantom') and single['status'] == 'ignored':
			ops.append(('ignore', single, single, []))
		elif single['file_group'] == 'new' and single['status'] == 'modified':
			ops.append(('create', None, single, []))
		else:
			print('unhandled %s/%s for %s' % (single['file_group'], single['status'], single['filepath']))

	timediff = Stats()
	for op, source, target, warn in ops:
		if source == target:
			if source['file_group'] not in ('existing', 'phantom'):
				warn.append('path not existing, but %s/%s' % (source['file_group'], source['status']))

		if source is not None:
			if source != target and (source['file_group'] != 'existing' or source['status'] != 'deleted'):
				warn.append('source not existing/deleted (probably temporary)')
			if source['before'] is None:
				warn.append('phantom source (probably recentfiles.py)')
			src = { 'dump': source['before'], 'filepath': source['filepath'] }
			time = source['time']
			append_warnings(warn, warnings, source)
		else:
			src = None

		if target is not None:
			if source != target and (target['file_group'] != 'new' or target['status'] != 'modified'):
				warn.append('target not new/modified, but %s/%s (probably overwrites something)' % (target['file_group'], target['status']))
			if target['after'] is None:
				warn.append('elusive file missing from dump')
			if target['original_filename'] is not None:
				warn.append('"untracked" file has original_filename %s' % target['original_filename'])
			if target['traceable_filename'] is not None:
				warn.append('"untracked" file has traceable_filename %s' % target['traceable_filename'])
			tgt = { 'dump': target['after'], 'filepath': target['filepath'] }
			time = target['time']
			append_warnings(warn, warnings, target)
		else:
			tgt = None

		if source is not None and target is not None and source['time'] is not None and target['time'] is not None:
			timediff.update(abs(source['time'] - target['time']))
			time = mean([source['time'], target['time']])
		print(json.dumps({ 'operation': op, 'warnings': warn,
			'time': time, 'source': src, 'target': tgt}))
	# note expected mean here is exactly zero when tracking, because we expect
	# the sample to not touch a file after moving it. for fully untracked
	# operation, the deletion time is None to begin with.
	# only expected difference is Windows time to filesystem time, seen when
	# encryption is tracked but moving isn't.
	print(timediff.aggregate_statistics())
