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
MAX_DURATION = timedelta(seconds=10)
USERDIR = 'C:\\Users\\cuckoo'
MAX_TIME_DIFF = 10 # seconds
MAX_DURATION_DIFF = 1 # seconds

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

class FileStatus:
	def __init__(self, status, start=None, end=None):
		self.status = status
		self.start = start
		self.end = end

	def duration(self):
		if self.end is None or self.start is None:
			return None
		return self.end - self.start

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
		yield 'filename case changed: %s / %s' % (base['filepath'], disk['filepath'])
	if disk['md5'] == base['md5'] and (disk['time_create'] != base['time_create']
			or disk['time_write'] != base['time_write']):
		yield 'ctime / mtime changed on ignored file: %d, %d / %d, %d' % (
				base['time_create'], base['time_write'],
				disk['time_create'], disk['time_write'])

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
				fs[path] = FileStatus('created', start_time, end_time)
			elif disk['md5'] != base['md5']:
				fs[path] = FileStatus('modified', start_time, end_time)
			else:
				fs[path] = FileStatus('ignored')
		else:
			fs[path] = FileStatus('deleted')
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
	return temp.get('fileops')

fileops_to_filestatus = {
	'nonexistent': {
		'create': ('created', None),
		'recreate': ('created', 'recreate nonexistent file (should be create)'),
		'delete': ('nonexistent', 'deleting nonexistent file'),
		# FIXME this happens due to recentfiles.py
		'write': ('created', 'write to nonexistent file'),
		'move_to': ('created', None)
	}, 'created': {
		'create': ('created', 'create existing file (should be recreate)'),
		'recreate': ('created', None),
		'delete': ('temp', None),
		'write': ('created', None),
		'move_to': ('created', None)
	}, 'temp': {
		'create': ('created', None),
		'recreate': ('created', 'recreate nonexistent file (should be create)'),
		'delete': ('temp', '(deleting nonexistent file)'),
		'write': ('created', 'write to nonexistent file'),
		'move_to': ('created', None)
	}, 'ignored': {
		'create': ('created', 'create existing file (should be recreate)'),
		'recreate': ('modified', None),
		'delete': ('deleted', None),
		'write': ('modified', None),
		'move_to': ('modified', None)
	}, 'modified': {
		'create': ('created', 'create existing file (should be recreate)'),
		'recreate': ('modified', None),
		'delete': ('deleted', None),
		'write': ('modified', None),
		'move_to': ('modified', None)
	}, 'deleted': {
		'create': ('modified', None),
		'recreate': ('modified', 'recreate nonexistent file (should be create)'),
		'delete': ('deleted', '(deleting nonexistent file)'),
		'write': ('modified', 'write to nonexistent file'),
		'move_to': ('modified', None)
	}
}

def iterate_fileops(fileops, analysis_start):
	prev_time = analysis_start
	for event in fileops:
		time = vm_to_utc(event['time'])
		assert time >= prev_time # events need to be sorted
		prev_time = time

		op = event['op']
		if op == 'file_created':
			yield time, 'create', event['path']
		elif op == 'file_written':
			yield time, 'write', event['path']
		elif op == 'file_deleted':
			yield time, 'delete', event['path']
		elif op == 'file_recreated':
			yield time, 'recreate', event['path']
		elif op == 'file_moved':
			# TODO if "from", check that it exists
			yield time, 'delete', event['from']
			yield time, 'move_to', event['to']
		elif op == 'file_copied':
			yield time, 'move_to', event['to']
		elif not op.startswith('directory_'):
			raise 'unknown fileop %s' % op

def parse_fileops(base, fileops, analysis_start):
	filestatus = { path: FileStatus('ignored') for path in base.keys() }
	warn = defaultdict(list)

	for time, event, path in iterate_fileops(fileops, analysis_start):
		normpath = path.lower()
		if not normpath.startswith(USERDIR.lower()) or normpath.startswith(
				(USERDIR + '\\AppData').lower()):
			continue

		if normpath not in filestatus:
			filestatus[normpath] = FileStatus('nonexistent')
		fs = filestatus[normpath]
		fs.status, warning = fileops_to_filestatus[fs.status][event]
		if fs.start is None:
			fs.start = time
		assert time >= fs.start
		if fs.end is None or fs.end < time:
			fs.end = time
		if warning is not None:
			warn[normpath] += ['%s at %s' % (warning, time)]
	return filestatus, warn

def check_duration(status, warnings):
	for path in status.keys():
		duration = status[path].duration()
		if duration is not None and duration > MAX_DURATION:
			warnings[path].append('operation took %s (%s to %s)' % (duration,
					status[path].start, status[path].end))

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

def format_status(filestatus, duration=None):
	if duration is None:
		duration = filestatus.duration()
	return { 'status': filestatus.status, 'time': filestatus.time(),
			'duration': duration.total_seconds() if duration is not None else None }

if len(sys.argv) < 3:
	sys.stderr.write('usage: python meta.py /path/to/analyses task-id...\n')
	sys.exit(1)
analyses = sys.argv[1]
tasks = sys.argv[2:]

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
	fileops = load_report(report)
	if fileops is None:
		sys.stderr.write('"fileops" key missing in report!\n' % manifest)
		sys.stderr.write('cuckoo is probably missing the custom fileops.py\n')
		sys.stderr.write('processing module. information will be missing.\n')
		fileops = []

	task_meta, virtual_start_time, real_start_time = load_task_info(task_info)
	assert task_meta['id'] == int(task)
	file_meta, status_manifest, warn_manifest = parse_manifest(base, manifest,
			task, real_start_time, virtual_start_time)
	status_fileops, warn_fileops = parse_fileops(base, fileops,
			virtual_start_time)
	check_duration(status_manifest, warn_manifest)
	check_duration(status_fileops, warn_fileops)
	paths = set(status_manifest.keys()) | set(status_fileops.keys())
	warnings = { p: warn_manifest[p] + warn_fileops[p] for p in paths }

	delta_stats = Stats()
	duration_stats = Stats()
	status = dict()
	for path in paths:
		fs = status_manifest.get(path)
		ops = status_fileops.get(path)

		if fs is None:
			warnings[path].append('missing in filesystem manifests')
			status[path] = format_status(ops)
			continue
		if ops is None:
			warnings[path].append('missing in fileops')
			status[path] = format_status(fs)
			continue

		if fs.status != ops.status:
			warnings[path].append('%s on filesystem, but fileops indicate %s' %
					(ops.status, ops.status))

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

		# times are expected to always differ a bit. monitor that inconsistency
		# with some statistics.
		if fs.time() is not None and ops.time() is not None:
			delta = fs.time() - ops.time()
			delta_stats.update(delta)
			if delta > MAX_TIME_DIFF:
				warnings[p].append('time difference too big: %f / %f' % (
						fs.time(), ops.time()))
		if fs.duration() is not None and ops.duration() is not None:
			delta = fs.duration().total_seconds() - ops.duration().total_seconds()
			duration_stats.update(delta)
			if delta > MAX_DURATION_DIFF:
				warnings[p].append('duration difference too big: %f / %f' % (
						fs.duration(), ops.duration()))

	for path in paths:
		if path not in file_meta:
			file_meta[path] = {}
		file_meta[path].update(status[path])
	with io.open('%s.json' % task, 'w') as fd:
		json.dump(file_meta, fd)

	# FIXME write structured warnings to a JSON file
	for path, warns in warnings.items():
		if warns == []:
			continue
		print('#%s %s:' % (task, path))
		for warn in warns:
			print('  %s' % warn)
	# FIXME write these to a JSON file, too
	print('#%s: %s' % (task, task_meta))
	print('  time difference: %f ±%f (n=%d)' % (delta_stats.mean(),
			delta_stats.stdev(), delta_stats.n()))
	print('  duration difference: %f ±%f (n=%d)' % (duration_stats.mean(),
			duration_stats.stdev(), duration_stats.n()))
