import io
import os
import json
from pytz import timezone
from collections import defaultdict
from datetime import datetime, timedelta

# somewhere in the Middle Ages, because... Microsoft
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone('UTC'))

def ntfs_to_utc(time):
	# 100ns intervals since 1601-01-01
	# (https://www.tuxera.com/community/ntfs-3g-advanced/extended-attributes/)
	# manual rounding because, due to intelligent choice of range in Redmond,
	# the timestamp value is already beyond what's exactly representable in
	# double-precision as of 2019
	# at least the values are UTC not localtime here
	return NTFS_EPOCH + timedelta(microseconds=(time + 5) / 10)

class FileTrackingState:
	# group:
	#   existing: path already existed before the analysis (according to the
	#             pre-analsysis filesystem manifest)
	#   new: path was created during the analysis (usually by the sample)
	#   phantom: path must have been created before the analysis started (eg.
	#            by recentfiles.py or by Windows)
	#   inconsistent: impossible operations, indicative of incorrect ProcMon
	#                 tracking information, were observed for this path
	# status:
	#   ignored: file wasn't touched during analysis
	#   modified: file content was changed
	#   deleted: file was deleted
	# note that "new/ignored" and "phantom/ignored" are logically impossible.
	# they are used internally, so if they show up, there's a logic bug
	# somwhere. files that would be "phantom/ignored" show up as
	# inconsistencies between manifests and fileops.
	def __init__(self, group, status, start=None, end=None, duration=None):
		self.group = group
		self.status = status
		if start is not None:
			self.start = start
		elif duration is not None:
			self.start = end - duration
		else:
			self.start = None
		self.end = end

	def duration(self):
		if self.end is None or self.start is None:
			return None
		return (self.end - self.start).total_seconds()

	def time(self):
		return self.end.timestamp() if self.end is not None else None

def load_manifest(file):
	by_path = dict()
	with io.open(file, 'rb') as infile:
		for line in infile:
			data = json.loads(line)
			by_path[data['filepath'].lower()] = data
	return by_path

def check_before_after(base, disk):
	if disk['filepath'] != base['filepath']:
		yield ('filename_case_changed', 'filename case changed: %s / %s'
				% (base['filepath'], disk['filepath']))
	if disk['md5'] == base['md5'] and (disk['time_create'] != base['time_create']
			or disk['time_write'] != base['time_write']):
		yield ('unmodified_utimes_changed',
				'ctime / mtime changed on ignored file: %d, %d / %d, %d'
				% (base['time_create'], base['time_write'],
				disk['time_create'], disk['time_write']))

def parse_manifest(base_manifest, disk_manifest, prefix, virtual_start, real_start):
	# filesystem uses the real (initial) UTC time even though the Windows
	# clock is set to the virtual time before the actual analysis starts
	fs_time_delta = virtual_start - real_start
	fs = dict()
	warn = defaultdict(list)
	metadata = dict()

	for path in set(base_manifest.keys()) | set(disk_manifest.keys()):
		base = base_manifest.get(path)
		disk = disk_manifest.get(path)

		meta = { 'before': None, 'after': None }
		if base is not None:
			meta['before'] = base['path']
			meta['filepath'] = base['filepath']
		if disk is not None:
			meta['after'] = os.path.normpath(os.path.join(prefix, disk['path']))
			meta['filepath'] = disk['filepath']
		if base is not None and disk is not None:
			warn[path] += check_before_after(base, disk)
		metadata[path] = meta

		if disk is not None:
			start_time = ntfs_to_utc(disk['time_create']) - fs_time_delta
			end_time = ntfs_to_utc(disk['time_write']) - fs_time_delta
			if start_time < virtual_start:
				# an existing file was overwritten (and possibly moved), so
				# creation time isn't indicative of the start of the write
				# operation. indicate missing value instead.
				start_time = None

			if base is None:
				# assume "new", ie. created during analysis. might also be "phantom".
				fs[path] = FileTrackingState('new', 'modified', start_time, end_time)
			elif disk['md5'] != base['md5']:
				fs[path] = FileTrackingState('existing', 'modified', start_time, end_time)
			else:
				fs[path] = FileTrackingState('existing', 'ignored')
		else:
			fs[path] = FileTrackingState('existing', 'deleted')
	return metadata, fs, warn
