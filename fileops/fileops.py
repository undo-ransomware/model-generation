import io
import os
import sys
import json
from pytz import timezone
from math import sqrt, nan, inf
from datetime import datetime, timedelta
from dateutil import parser as dateparser
from collections import defaultdict, Counter
from report_parser import load_report, parse_fileops, vm_to_utc
from manifest_parser import load_manifest, parse_manifest
from merge import merge_status
from config import LOCALTIME_HOST

UTC = timezone('UTC')

def isoparse(isotime):
	return dateparser.isoparse(isotime).timestamp()

def host_to_utc(time):
	# also fails for times during the late-night DST-end changeover, because
	# cuckoo wisely doesn't include a timezone :(
	return datetime.fromtimestamp(time, LOCALTIME_HOST).astimezone(UTC)

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

	if not os.path.isfile(task_info):
		sys.stderr.write('%s doesn\'t exist!\n' % task_info)
		sys.stderr.write('%s probably isn\'t a valid task ID\n' % task)
		sys.exit(1)
	task_meta, virtual_start_time, real_start_time, real_stop_time = \
			load_task_info(task_info)
	virtual_stop_time = virtual_start_time - real_start_time + real_stop_time
	assert task_meta['id'] == int(task)
	if not os.path.isfile(manifest):
		sys.stderr.write('%s doesn\'t exist!\n' % manifest)
		sys.stderr.write('please run dump.py ON THE CUCKOO SERVER:\n')
		sys.stderr.write('  python dump.py %s\n' % task)
		sys.exit(1)
	disk_manifest = load_manifest(manifest)
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

	file_meta, status_manifest, traceable_name, warn_manifest = \
			parse_manifest(base, disk_manifest, task, real_start_time, \
					virtual_start_time)
	status_fileops, orig_filename, warn_fileops = parse_fileops(base, fileops,
			virtual_start_time)
	status, warnings, delta_stats, duration_stats, last_operation = \
			merge_status(status_manifest, warn_manifest, status_fileops,
					warn_fileops, virtual_start_time, real_start_time,
					virtual_stop_time, real_stop_time)

	for path, tracking in status.items():
		if path in status and status[path].group == 'phantom':
			if path in orig_filename:
				org = 'origin = %s' % orig_filename[path]
			else:
				org = 'unknown origin'
			warnings[path].append(('phantom_file', 'phantom file, %s' % org))

		if path not in file_meta:
			file_meta[path] = {}
		file_meta[path].update({
				'file_group': tracking.group, 'status': tracking.status,
				'time': tracking.time(), 'duration': tracking.duration(),
				'traceable_filename': traceable_name[path]
						if path in traceable_name else None,
				'original_filename': orig_filename[path]
						if path in orig_filename else None })

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
	print('  warnings:')
	for warn, count in Counter([warn[0]
			for item in warnings.values() for warn in item]).items():
		print('    %s %d' % (warn, count))
	print('')
