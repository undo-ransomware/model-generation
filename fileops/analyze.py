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

def track_by(fileops, tracking_key):
	# create a copy of the list so we can delete items from the original set
	# during the iteration
	tracked = [(data['filepath'].lower(), data[tracking_key].lower())
			for data in fileops.values() if data[tracking_key] is not None]
	for tgt, src in tracked:
		if src not in fileops:
			# file was created in temp directory and then moved to target.
			# note that moving an existing file to the temp directory would
			# be tracked.
			continue
		yield fileops[src], fileops[tgt]
		del fileops[src]
		del fileops[tgt]

def summarize(fileops):
	# tracked renames, ie. where we have fileops showing the rename
	for source, target in track_by(fileops, 'original_filename'):
		if target['traceable_filename'] is not None:
			warn = []
			if target['traceable_filename'].lower() != source['filepath'].lower():
				warn = ['target name traces to %s instead'
						% target['traceable_filename']]
			yield 'modify_addext', source, target, warn
		else:
			yield 'modify_rename', source, target, []

	# untracked renames we can infer by the sample using derived names
	for source, target in track_by(fileops, 'traceable_filename'):
		# TODO remove phantom_modify and phantom_deletion
		yield 'modify_addext', source, target, []

	# untracked renames where we cannot infer the original name, as well as
	# just general creations and deletions
	for single in fileops.values():
		if single['file_group'] in ('existing', 'phantom'):
			if single['status'] == 'modified':
				yield 'modify', single, single, []
			elif single['status'] == 'deleted':
				yield 'delete', single, None, []
			elif single['status'] == 'ignored':
				# phantom/ignored should never be reported
				assert single['file_group'] == 'existing'
				yield 'ignore', single, single, []
			else:
				assert False # no other values defined
		elif single['file_group'] == 'new':
			if single['status'] == 'modified':
				yield 'create', None, single, []
			else: # new/ignored should never appear
				assert single['status'] == 'deleted'
		else:
			assert False # no other values defined

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

	timediff = Stats()
	for op, source, target, warn in summarize(fileops):
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
