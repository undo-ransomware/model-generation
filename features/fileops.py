import io
import os
import sys
import json
from pytz import timezone
from math import sqrt, nan, inf
from collections import defaultdict
from datetime import datetime, timedelta
from dateutil import parser as dateparser

UTC = timezone('UTC')
LOCALTIME_VM = timezone('Europe/Berlin')
LOCALTIME_HOST = timezone('Europe/Berlin')
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=UTC) # somewhere in the Middle Ages, because... Microsoft
MAX_DURATION = 10 # seconds
USERDIR = 'C:\\Users\\cuckoo'
MAX_TIME_DIFF = 10 # seconds
MAX_DURATION_DIFF = 1 # seconds
WINDOWS_JUNK = ['AppData', 'NTUSER.DAT']

def isoparse(isotime):
	return dateparser.isoparse(isotime).timestamp()

def vm_to_utc(time):
	# fails for times during the late-night DST-end changeover
	# just don't run analyses during that time. chances are the ransomware
	# will also screw up dates during DST changes. after all, TeslaCrypt
	# doesn't even handle day rollover at the end of the month...
	return datetime.fromtimestamp(time, LOCALTIME_VM).astimezone(UTC)

def host_to_utc(time):
	# also fails for times during the late-night DST-end changeover, because
	# cuckoo wisely doesn't include a timezone :(
	return datetime.fromtimestamp(time, LOCALTIME_HOST).astimezone(UTC)

def ntfs_to_utc(time):
	# 100ns intervals since 1601-01-01
	# (https://www.tuxera.com/community/ntfs-3g-advanced/extended-attributes/)
	# manual rounding because, due to intelligent choice of range in Redmond,
	# the timestamp value is already beyond what's exactly representable in
	# double-precision as of 2019
	# at least the values are UTC not localtime here
	return NTFS_EPOCH + timedelta(microseconds=(time + 5) / 10)

def is_windows_junk(path):
	if not path.startswith(USERDIR.lower()):
		return True
	for junk in WINDOWS_JUNK:
		if path.startswith(('%s\\%s' % (USERDIR, junk)).lower()):
			return True
	return False

class FileStatus:
	def __init__(self, name, exists_before, exists_after, modified):
		self.name = name
		self.exists_before = exists_before
		self.exists_after = exists_after
		self.modified = modified

class FileTrackingState:
	# group:
	#   existing: path already existed before the analysis (according to the
	#             pre-analsysis filesystem manifest)
	#   new: path was created during the analysis (usually by the sample)
	#   phantom: path must have been created before the analysis started (eg.
	#            by recentfiles.py or by Windows)
	# status:
	#   ignored: file wasn't touched during analysis
	#   modified: file content was changed
	#   deleted: file was deleted
	# note that "new/ignored" and "phantom/ignored" are logically impossible.
	# "new/ignored" is used internally, so if it shows up, there's a logic bug
	# somwhere. files that would be "phantom/ignored" show up as
	# inconsistencies between manifests and fileops.
	def __init__(self, group, status, start=None, end=None):
		self.group = group
		self.status = status
		self.start = start
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

def parse_manifest(base_manifest, manifest, prefix, virtual_start, real_start):
	# filesystem uses the real (initial) UTC time even though the Windows
	# clock is set to the virtual time before the actual analysis starts
	fs_time_delta = virtual_start - real_start
	disk_manifest = load_manifest(manifest)
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

def load_task_info(file):
	with io.open(file, 'rb') as fd:
		temp = json.load(fd)
	# time that the Windows clock is set to during the analysis (usually just
	# the submission time). fileops use this timeline.
	virtual_start_time = vm_to_utc(isoparse(temp['clock']['$dt']))
	# time on the server when analysis actually started. this is the initial
	# time on the VM when it starts, and somehow the filesystem still uses
	# this timeline even after setting the Windows clock.
	real_start_time = host_to_utc(isoparse(temp['started_on']['$dt']))
	metadata = { key: temp[key] for key in ['route', 'timeout', 'duration', 'id'] }
	metadata['virtual_start_time'] = virtual_start_time.timestamp()
	metadata['real_start_time'] = real_start_time.timestamp()
	return metadata, virtual_start_time, real_start_time

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

def check_duration(status, warnings):
	for path in status.keys():
		duration = status[path].duration()
		if duration is not None and duration > MAX_DURATION:
			warnings[path].append(('long_operation',
					'operation took %s (%s to %s)'
					% (duration, status[path].start, status[path].end)))

class Stats:
	def __init__(self):
		self._n = 0
		self._mean = 0.0
		self._var = 0.0

	# this is Welford's method, which is numerically stable. see
	# https://jonisalonen.com/2013/deriving-welfords-method-for-computing-variance/
	def update(self, value):
		self._n += 1
		old_mean = self._mean
		self._mean += (value - self._mean) / self._n
		self._var += (value - self._mean) * (value - old_mean)

	def n(self):
		return self._n

	def mean(self):
		return self._mean if self._n > 1 else nan

	def stdev(self):
		if self._n == 0:
			return nan
		if self._n == 1:
			return inf
		return sqrt(self._var / (self._n - 1))

	def aggregate_statistics(self):
		if self._n == 0:
			return None
		return { 'mean': self.mean(), 'stdev': self.stdev(), 'n': self.n() }

def format_status(tracking, duration=None):
	if duration is None:
		duration = tracking.duration()
	return { 'file_group': tracking.group, 'status': tracking.status,
			'time': tracking.time(), 'duration': duration }

if len(sys.argv) < 4:
	sys.stderr.write('usage: python meta.py /path/to/analyses path/to/output task-id...\n')
	sys.exit(1)
analyses = sys.argv[1]
output = sys.argv[2]
tasks = sys.argv[3:]

base_manifest = os.path.join(analyses, 'base.json')
if not os.path.isfile(base_manifest):
	sys.stderr.write('%s doesn\'t exist!\n' % base_manifest)
	sys.stderr.write('either %s isn\'t your analyses directory,\n')
	sys.stderr.write('or dump.py wasn\'t setup correctly.\n')
	sys.exit(1)
base = load_manifest(base_manifest)

for task in tasks:
	manifest = os.path.join(analyses, task, 'disk.json')
	task_info = os.path.join(analyses, task, 'task.json')
	report = os.path.join(analyses, task, 'reports', 'report.json')
	if not os.path.isfile(manifest):
		sys.stderr.write('%s doesn\'t exist!\n' % task_info)
		sys.stderr.write('%s probably isn\'t a valid task ID\n' % task)
		sys.exit(1)
	if not os.path.isfile(task_info):
		sys.stderr.write('%s doesn\'t exist!\n' % manifest)
		sys.stderr.write('please run dump.py ON THE CUCKOO SERVER:\n')
		sys.stderr.write('  python dump.py %s\n' % task)
		sys.exit(1)
	if not os.path.isfile(report):
		sys.stderr.write('%s doesn\'t exist!\n' % report)
		sys.stderr.write('reprocess the task (on the cuckoo server):\n')
		sys.stderr.write('  cuckoo process -r %s\n' % task)
		sys.exit(1)
	targetinfo, fileops = load_report(report)
	if fileops is None:
		sys.stderr.write('"fileops" key missing in report!\n' % manifest)
		sys.stderr.write('cuckoo is probably missing the custom fileops.py\n')
		sys.stderr.write('processing module. information will be missing.\n')
		fileops = []

	task_meta, virtual_start_time, real_start_time = load_task_info(task_info)
	assert task_meta['id'] == int(task)
	file_meta, status_manifest, warn_manifest = parse_manifest(base, manifest,
			task, real_start_time, virtual_start_time)
	status_fileops, orig_filename, warn_fileops = parse_fileops(base, fileops,
			virtual_start_time)
	check_duration(status_manifest, warn_manifest)
	check_duration(status_fileops, warn_fileops)
	paths = { p
			for p in set(status_manifest.keys()) | set(status_fileops.keys())
			if not is_windows_junk(p) }
	warnings = { p: warn_manifest[p] + warn_fileops[p] for p in paths }

	delta_stats = Stats()
	duration_stats = Stats()
	status = dict()
	for path in paths:
		fs = status_manifest.get(path)
		ops = status_fileops.get(path)

		if ops is None:
			warnings[path].append(('missing_fileops',
					'missing in fileops, %s/%s on filesystem'
					% (fs.group, fs.status)))
			status[path] = format_status(fs)
			continue
		if ops.group == 'phantom':
			if path in orig_filename:
				org = 'origin = %s' % orig_filename[path]
			else:
				org = 'unknown origin'
			warnings[path].append(('phantom_file', 'phantom file, %s' % org))
		if fs is None:
			warnings[path].append(('missing_filesystem',
					'missing in filesystem, fileops indicate %s/%s'
					% (ops.group, ops.status)))
			status[path] = format_status(ops)
			continue

		if fs.status != ops.status:
			warnings[path].append(('inconsistent_state',
					'%s/%s on filesystem, but fileops indicate %s/%s' %
					(fs.group, fs.status, ops.group, ops.status)))

		# fileops is more reliable for duration of operations because it knows
		# the actual operations that took place. it's also the only way to get
		# a duration for samples that overwrite existing files.
		duration = ops.duration() if ops.duration() is not None else fs.duration()
		# use filesystem status with fileops timestamp. only fileops has
		# timestamps for deletions, so we need to use them for everything
		# else, too, for maximum consistency.
		# assuming that a sample either evades all monitoring or none of it,
		# either all files hit the "missing in fileops" case, or all have good
		# fileops values. thus there should never be a mix of files with
		# fileops and filesystem manifest times.
		status[path] = format_status(fs, duration)

		# times always differ a bit. statistically monitor that inconsistency.
		if fs.time() is not None and ops.time() is not None:
			delta = fs.time() - ops.time()
			delta_stats.update(delta)
			if abs(delta) > MAX_TIME_DIFF:
				warnings[path].append(('timestamp_differs',
						'timestamp discrepancy too big: %f / %f'
						% (fs.time(), ops.time())))
		if fs.duration() is not None and ops.duration() is not None:
			delta = fs.duration() - ops.duration()
			duration_stats.update(delta)
			if abs(delta) > MAX_DURATION_DIFF:
				warnings[path].append(('duration_differs',
						'duration discrepancy too big: %f / %f'
						% (fs.duration(), ops.duration())))

	for path in paths:
		if path not in file_meta:
			file_meta[path] = {}
		file_meta[path].update(status[path])
		file_meta[path]['original_filename'] = orig_filename[path] \
				if path in orig_filename else None

	taskdir = os.path.join(output, task)
	if not os.path.isdir(taskdir):
		os.mkdir(taskdir)
	with io.open(os.path.join(taskdir, 'fileops.json'), 'w') as fd:
		for path, meta in file_meta.items():
			json.dump(meta, fd)
			fd.write('\n')
	nwarn = 0
	with io.open(os.path.join(taskdir, 'warnings.json'), 'w') as fd:
		for path in file_meta.keys():
			if path not in warnings or warnings[path] == []:
				continue
			warns = warnings[path]
			if warns == []:
				continue
			for code, msg in warns:
				json.dump({ 'path': path, 'code': code, 'msg': msg }, fd)
				fd.write('\n')
			nwarn += len(warns)

	task_meta['timestamp_diff'] = delta_stats.aggregate_statistics()
	task_meta['duration_diff'] = duration_stats.aggregate_statistics()
	task_meta['sample'] = targetinfo['md5']
	with io.open(os.path.join(taskdir, 'taskinfo.json'), 'w') as fd:
		json.dump(task_meta, fd)
	print('#%s: %s, %d warnings' % (task, targetinfo['md5'], nwarn))
	print('  time difference: %f ±%f (n=%d)' % (delta_stats.mean(),
			delta_stats.stdev(), delta_stats.n()))
	print('  duration difference: %f ±%f (n=%d)' % (duration_stats.mean(),
			duration_stats.stdev(), duration_stats.n()))
