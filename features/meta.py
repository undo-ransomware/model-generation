import io
import os
import sys
import json
from pytz import timezone
from collections import defaultdict
from datetime import datetime, timedelta

UTC = timezone('UTC')
LOCALTIME_VM = timezone('Europe/Berlin')
LOCALTIME_CUCKOO = timezone('Europe/Berlin')
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=UTC) # somewhere in the Middle Ages, because... Microsoft
MAX_DURATION = timedelta(seconds=1)

def vm_to_utc(time):
	# fails for times during the late-night DST-end changeover
	# just don't run analyses during that time. chances are the ransomware
	# will also screw up dates during DST changes. after all, TeslaCrypt
	# doesn't even handle day rollover at the end of the month...
	return datetime.fromtimestamp(time, LOCALTIME_VM).astimezone(UTC)

def cuckoo_to_utc(time):
	# also fails for times during the late-night DST-end changeover, because
	# cuckoo wisely doesn't include a timezone in the database field :(
	return datetime.fromtimestamp(time, LOCALTIME_CUCKOO).astimezone(UTC)

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
	
	@classmethod
	def from_manifest(cls, status, disk, analysis_start_time):
		if analysis_start_time is not None:
			start_time = ntfs_to_utc(disk['time_create'])
			end_time = ntfs_to_utc(disk['time_write'])
			if start_time < analysis_start_time:
				# existing file was overwritten (and possibly moved), so
				# creation time isn't indicative of the start of the write
				# operation. indicate missing value instead.
				start_time = None
		else:
			start_time = end_time = None
		return cls(status, start_time, end_time)

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

def parse_manifest(base_manifest, manifest, prefix, analysis_start):
	disk_manifest = load_manifest(manifest)
	fs = dict()
	warn = defaultdict(list)
	metainfo = dict()

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
		metainfo[path] = meta

		if disk is None:
			fs[path] = FileStatus.from_manifest('deleted', base, None)
		elif base is None:
			fs[path] = FileStatus.from_manifest('created', disk, analysis_start)
		elif disk['md5'] != base['md5']:
			fs[path] = FileStatus.from_manifest('modified', disk, analysis_start)
		else:
			fs[path] = FileStatus.from_manifest('ignored', disk, None)
	return metainfo, fs, warn

def load_report(file):
	with io.open(file, 'rb') as fd:
		temp = json.load(fd)
	# TODO "dropped" might be useful to reconstruct temporary files
	return temp['info'], temp.get('fileops', None)

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
	report = os.path.join(analyses, task, 'reports', 'report.json')
	if not os.path.isfile(manifest) or not os.path.isfile(report):
		sys.stderr.write('%s or %s doesn\'t exist!\n' % (manifest, report))
		sys.stderr.write('either %s isn\'t a task ID,\n' % task)
		sys.stderr.write('or dump.py wasn\'t run on it.\n')
		sys.exit(1)
	info, fileops = load_report(report)
	if fileops is None:
		sys.stderr.write('"fileops" key missing in report!\n' % manifest)
		sys.stderr.write('cuckoo is probably missing the custom fileops.py\n')
		sys.stderr.write('processing module.\n')
	analysis_start_time = cuckoo_to_utc(info['started'])
	
	metainfo, status_manifest, warnings = parse_manifest(base, manifest, task,
			analysis_start_time)
	status = status_manifest # TODO create status_fileops and compare
	for path in status.keys():
		duration = status[path].duration()
		if duration is not None and duration > MAX_DURATION:
			warnings[path].append('operations took %s' % duration)
			warnings[path].append('times %s %s' % (status[path].start, status[path].end))
		print('%s %s t=%s' % (metainfo[path], status[path].status,
				status[path].time()))
	for path, warns in warnings.items():
		for warn in warns:
			sys.stderr.write('#%s %s: %s\n' % (task, path, warn))
