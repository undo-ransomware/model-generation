import io
import os
import sys
import json
from pytz import timezone
from collections import defaultdict
from datetime import datetime, timedelta
from dateutil import parser as dateparser

UTC = timezone('UTC')
LOCALTIME_VM = timezone('Europe/Berlin')
LOCALTIME_HOST = timezone('Europe/Berlin')
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=UTC) # somewhere in the Middle Ages, because... Microsoft
MAX_DURATION = timedelta(seconds=1)

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
	def __init__(self, status, start, end):
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
		base = base_manifest.get(path, None)
		disk = disk_manifest.get(path, None)

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
				fs[path] = FileStatus('ignored', None, None)
		else:
			fs[path] = FileStatus('deleted', None, None)
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
	return temp.get('fileops', None)

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
	
	run_meta, virtual_start_time, real_start_time = load_task_info(task_info)
	assert run_meta['id'] == int(task)
	file_meta, status_manifest, warnings = parse_manifest(base, manifest, task,
			real_start_time, virtual_start_time)
	status = status_manifest # TODO create status_fileops and compare

	for path in status.keys():
		duration = status[path].duration()
		if duration is not None and duration > MAX_DURATION:
			warnings[path].append('operation took %s (%s to %s)' % (duration,
					status[path].start, status[path].end))
		print('%s %s t=%s' % (file_meta[path], status[path].status,
				status[path].time()))
	for path, warns in warnings.items():
		for warn in warns:
			sys.stderr.write('#%s %s: %s\n' % (task, path, warn))
