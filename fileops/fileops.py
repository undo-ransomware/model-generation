import io
import os
import sys
import json
from pytz import timezone
from math import sqrt, nan, inf
from collections import defaultdict
from datetime import datetime, timedelta
from dateutil import parser as dateparser
from report_parser import load_report, parse_fileops, vm_to_utc
from manifest_parser import load_manifest, parse_manifest
from config import LOCALTIME_HOST, USERDIR, WINDOWS_JUNK, MAX_FILEOP_DURATION, \
		MAX_TIME_DIFF, MAX_DURATION_DIFF, TIMEOUT_MARGIN

UTC = timezone('UTC')

def isoparse(isotime):
	return dateparser.isoparse(isotime).timestamp()

def host_to_utc(time):
	# also fails for times during the late-night DST-end changeover, because
	# cuckoo wisely doesn't include a timezone :(
	return datetime.fromtimestamp(time, LOCALTIME_HOST).astimezone(UTC)

def is_windows_junk(path):
	if not path.startswith(USERDIR.lower()):
		return True
	for junk in WINDOWS_JUNK:
		if path.startswith(('%s\\%s' % (USERDIR, junk)).lower()):
			return True
	return False

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
	stop_time = host_to_utc(isoparse(temp['completed_on']['$dt']))
	metadata = { key: temp[key] for key in ['route', 'timeout', 'duration', 'id'] }
	metadata['virtual_start_time'] = virtual_start_time.timestamp()
	metadata['real_start_time'] = real_start_time.timestamp()
	metadata['real_stop_time'] = stop_time.timestamp()
	return metadata, virtual_start_time, real_start_time, stop_time

def check_duration(status, warnings):
	for path in status.keys():
		duration = status[path].duration()
		if duration is not None and duration > MAX_FILEOP_DURATION:
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

def merge_status(fs, ops, warn):
	if ops is None:
		warn.append(('missing_fileops', 'missing in fileops, %s/%s on filesystem'
				% (fs.group, fs.status)))
		return fs, None
	if fs is None:
		warn.append(('missing_filesystem',
				'missing in filesystem, fileops indicate %s/%s'
				% (ops.group, ops.status)))
		return ops, None

	if fs.status != ops.status:
		warn.append(('inconsistent_state',
				'%s/%s on filesystem, but fileops indicate %s/%s' %
				(fs.group, fs.status, ops.group, ops.status)))
	# times always differ a bit. statistically monitor that inconsistency.
	if fs.time() is not None and ops.time() is not None:
		delta = fs.time() - ops.time()
		delta_stats.update(delta)
		if abs(delta) > MAX_TIME_DIFF:
			warn.append(('timestamp_differs',
					'timestamp discrepancy too big: %f / %f'
					% (fs.time(), ops.time())))
	if fs.duration() is not None and ops.duration() is not None:
		delta = fs.duration() - ops.duration()
		duration_stats.update(delta)
		if abs(delta) > MAX_DURATION_DIFF:
			warn.append(('duration_differs',
					'duration discrepancy too big: %f / %f'
					% (fs.duration(), ops.duration())))

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
	return fs, duration

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

	task_meta, virtual_start_time, real_start_time, real_stop_time = \
			load_task_info(task_info)
	virtual_stop_time = virtual_start_time - real_start_time + real_stop_time
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
	last_operation = virtual_start_time
	status = dict()
	for path in paths:
		fs = status_manifest.get(path)
		ops = status_fileops.get(path)

		if ops is not None and ops.group == 'phantom':
			if path in orig_filename:
				org = 'origin = %s' % orig_filename[path]
			else:
				org = 'unknown origin'
			warnings[path].append(('phantom_file', 'phantom file, %s' % org))

		tracking, duration = merge_status(fs, ops, warnings[path])
		if duration is None:
			duration = tracking.duration()
		status[path] = { 'file_group': tracking.group, 'duration': duration,
				'status': tracking.status, 'time': tracking.time() }

		if tracking.end is not None:
			if tracking.end > last_operation:
				last_operation = tracking.end
			if tracking.end > virtual_stop_time:
				warnings[path].append(('impossible_timestamp',
						'operation at %f after nominal timeout at %f'
						% (tracking.time(), virtual_stop_time.timestamp())))
			elif virtual_stop_time - tracking.end < TIMEOUT_MARGIN:
				warnings[path].append(('timeout_margin',
						'operation at %f too close before timeout %f'
						% (tracking.time(), virtual_stop_time.timestamp())))

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
	task_meta['last_operation'] = last_operation.timestamp()
	with io.open(os.path.join(taskdir, 'taskinfo.json'), 'w') as fd:
		json.dump(task_meta, fd)
	print('#%s: %s, duration %ds, %d warnings'
			% (task, targetinfo['md5'], task_meta['duration'], nwarn))
	print('  time difference: %f ±%f (n=%d)' % (delta_stats.mean(),
			delta_stats.stdev(), delta_stats.n()))
	print('  duration difference: %f ±%f (n=%d)' % (duration_stats.mean(),
			duration_stats.stdev(), duration_stats.n()))
	print('  margin to analysis timeout: %s' % (virtual_stop_time - last_operation))
