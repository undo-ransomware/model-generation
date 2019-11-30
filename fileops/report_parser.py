import io
import os
import sys
import json
from pytz import timezone
from collections import defaultdict
from datetime import datetime
from manifest_parser import FileTrackingState
from config import LOCALTIME_VM

UTC = timezone('UTC')

def vm_to_utc(time):
	# fails for times during the late-night DST-end changeover
	# just don't run analyses during that time. chances are the ransomware
	# will also screw up dates during DST changes. after all, TeslaCrypt
	# doesn't even handle day rollover at the end of the month...
	return datetime.fromtimestamp(time, LOCALTIME_VM).astimezone(UTC)

def windows_dirname(path):
	return '\\'.join(path.split('\\')[:-1])

def load_report(file):
	with io.open(file, 'rb') as fd:
		temp = json.load(fd)
	# TODO "dropped" might also be useful, to reconstruct temporary files
	target = temp['target']['file']
	return target, temp.get('fileops')

class Tracker:
	def __init__(self, base):
		self.tracking = { path: FileTrackingState('existing', 'ignored')
				for path in base.keys() }
		self.warn = defaultdict(list)
		self.original_name = dict()

	def assume_exists(self, time, path, op):
		normpath = path.lower()
		if normpath not in self.tracking:
			# operation on a file we didn't know existed. assume it was created
			# by something before analysis start, cuckoo's recentfiles.py being
			# the usual culprit.
			self.tracking[normpath] = FileTrackingState('phantom', 'ignored')
		elif self.tracking[normpath].status == 'deleted':
			# operation on a file we know shouldn't exist, eg. because we saw
			# its deletion. still doesn't imply a ProcMon malfunction, but very
			# suspicious nevertheless.
			self.warn[normpath].append(('operation_on_nonexistent',
					'inconsistent %s for nonexistent file at %s' % (op, time)))
			self.tracking[normpath].group = 'inconsistent'

	def create(self, time, path, op):
		normpath = path.lower()
		if normpath in self.tracking and self.tracking[normpath].status != 'deleted':
			self.warn[normpath].append(('create_existing',
					'%s for existing file at %s' % (op, time)))
			self.tracking[normpath].group = 'inconsistent'

	def truncate(self, time, path, op):
		normpath = path.lower()
		if normpath not in self.tracking:
			self.tracking[normpath] = FileTrackingState('new', 'ignored')
		elif self.tracking[normpath].status == 'deleted':
			if self.tracking[normpath].group == 'phantom':
				self.warn[normpath].append(('phantom_recreate',
						'phantom filename reused by %s at %s' % (op, time)))
				self.tracking[normpath].group = 'new'
			self.tracking[normpath].status = 'modified'

	def delete(self, time, path, op):
		normpath = path.lower()
		if normpath not in self.tracking or self.tracking[normpath].status == 'deleted':
			# deletion of nonexistent file. indicative of strange programming
			# practices, but not of a ProcMon malfunction.
			self.warn[normpath].append(('delete_nonexistent',
					'pointless %s for nonexistent file at %s' % (op, time)))
		if normpath not in self.tracking:
			# deletion of a previously unknown file.
			# assume it existed as a phantom file. if it didn't, how did the
			# sample come up with its name?
			self.tracking[normpath] = FileTrackingState('phantom', 'deleted')
		self.tracking[normpath].status = 'deleted'

	def write(self, time, path, op):
		# write to deleted files handled in assume_exists above
		self.tracking[path.lower()].status = 'modified'

	def rename(self, time, old_path, new_path):
		old_normpath = old_path.lower()
		new_normpath = new_path.lower()
		# propagate inconsistency and phantom state
		if self.tracking[old_normpath].group == 'inconsistent':
			self.tracking[new_normpath].group = 'inconsistent'
		elif self.tracking[old_normpath].group == 'phantom':
			self.tracking[new_normpath].group = 'phantom'
		# record original filename. preserve case because for phantom files,
		# we cannot get it from the pre-analysis filesystem manifest.
		if old_normpath in self.original_name:
			self.original_name[new_normpath] = self.original_name[old_normpath]
			del self.original_name[old_normpath]
		else:
			self.original_name[new_normpath] = old_path
		# probably harmless, but good to know when it happens
		if windows_dirname(new_normpath) != windows_dirname(old_normpath):
			warn = ('move_across_dir',
					'moved across directories: %s -> %s at %s'
					% (old_normpath, new_normpath, time))
			self.warn[new_normpath].append(warn)
			self.warn[old_normpath].append(warn)

	def update_times(self, time, path):
		ts = self.tracking[path.lower()]
		if ts.start is None:
			ts.start = time
		assert time >= ts.start
		if ts.end is None or ts.end < time:
			ts.end = time

def parse_fileops(base, fileops, analysis_start):
	tracker = Tracker(base)

	prev_time = analysis_start
	for op in fileops:
		time = vm_to_utc(op['time'])
		assert time >= prev_time # events need to be sorted
		prev_time = time
		path = op['path'] if 'path' in op else op['from']

		try:
			event = op['op']
			if event == 'file_recreated' or event == 'file_written':
				tracker.assume_exists(time, path, event)
				tracker.write(time, path, event)
			elif event == 'file_created':
				tracker.create(time, path, event)
				tracker.truncate(time, path, event)
			elif event == 'file_deleted':
				tracker.delete(time, path, event)
			elif event == 'file_moved' or event == 'file_copied':
				new_path = op['to']
				tracker.assume_exists(time, path, event)
				tracker.truncate(time, new_path, event)
				tracker.write(time, new_path, event)
				tracker.rename(time, path, new_path)
				if event == 'file_moved':
					tracker.delete(time, path, event)
				tracker.update_times(time, new_path)
			elif event.startswith('directory_'):
				continue
			else:
				raise 'unknown fileop %s' % event
			tracker.update_times(time, path)
		except:
			sys.stderr.write(json.dumps(op))
			raise

	return tracker.tracking, tracker.original_name, tracker.warn
