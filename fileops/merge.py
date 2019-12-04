from datetime import timedelta
from math import sqrt, nan, inf
from manifest_parser import FileTrackingState
from config import USERDIR, WINDOWS_JUNK, MAX_FILEOP_DURATION, MAX_TIME_DIFF, \
		MAX_DURATION_DIFF, TIMEOUT_MARGIN

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

def merge_tracking_status(fs, ops, delta_stats, duration_stats):
	if ops is None:
		# all other cases that the filesystem manifest parser can report
		# involve existing files. if the report parser didn't catch those,
		# then there's a significant logic bug somewhere!
		assert fs.group == 'new' and fs.status == 'modified'
		fs.warn('phantom_creation', 'unmonitored file creation')
		return fs
	if fs is None:
		if (ops.group != 'phantom' and ops.group != 'new') or ops.status != 'deleted':
			# deleted phantom or temporary files never show up in the filesystem
			ops.warn('missing_in_filesystem',
					'missing in filesystem, fileops indicate %s/%s'
					% (ops.group, ops.status))
		return ops

	# prefer filesystem status because fileops tracking can be evaded
	if fs.group == 'new' and ops.group == 'phantom':
		# modified phantom file, expected to show up as new in the filesystem
		group = 'phantom'
	else:
		# group only depends on whether the file was there before. if the two
		# sources fail to agree on THAT, there's a serious logic bug
		# somewhere...
		assert fs.group == ops.group
		group = fs.group

	# fileops is more reliable for duration of operations because it knows
	# the actual operations that took place. it's also the only way to get
	# a duration for samples that overwrite existing files.
	dur = ops.duration() if ops.duration() is not None else fs.duration()
	# use filesystem status with fileops timestamp. only fileops has
	# timestamps for deletions, so we need to use them for everything
	# else, too, for maximum consistency.
	# assuming that a sample either evades all monitoring or none of it,
	# either all files hit the "missing in fileops" case, or all have good
	# fileops values. thus there should never be a mix of files with
	# fileops and filesystem manifest times.
	status = FileTrackingState(group, fs.status, end=ops.end,
			duration=timedelta(seconds=dur) if dur is not None else None)
	# propagate diagnostics
	if ops.inconsistent:
		# something weird happened. all bets are off :(
		status.inconsistent = True
	for code, msg in fs.warnings.items():
		status.warn(code, msg)
	for code, msg in ops.warnings.items():
		status.warn(code, msg)

	if fs.status == 'deleted' and ops.status != 'deleted':
		status.warn('phantom_deletion',
				'unmonitored file deletion, expected %s/%s'
				% (fs.group, fs.status))
	elif fs.status == 'modified' and ops.status == 'ignored':
		status.warn('phantom_modify', 'unmonitored file modification')
	elif fs.status != 'deleted' and ops.status == 'deleted':
		status.warn('failed_deletion', 'deleted file still exists as %s/%s'
				% (fs.group, fs.status))
	elif fs.status != ops.status:
		status.warn('inconsistent_state',
				'%s/%s on filesystem, but fileops indicate %s/%s' %
				(fs.group, fs.status, ops.group, ops.status))

	# times always differ a bit. statistically monitor that inconsistency.
	if fs.time() is not None and ops.time() is not None:
		delta = fs.time() - ops.time()
		delta_stats.update(delta)
		if abs(delta) > MAX_TIME_DIFF:
			status.warn('timestamp_differs',
					'timestamp discrepancy too big: %f / %f'
					% (fs.time(), ops.time()))
	if fs.duration() is not None and ops.duration() is not None:
		delta = fs.duration() - ops.duration()
		duration_stats.update(delta)
		if abs(delta) > MAX_DURATION_DIFF:
			status.warn('duration_differs',
					'duration discrepancy too big: %f / %f'
					% (fs.duration(), ops.duration()))
	return status

def is_windows_junk(path):
	if not path.startswith(USERDIR.lower()):
		return True
	for junk in WINDOWS_JUNK:
		if path.startswith(('%s\\%s' % (USERDIR, junk)).lower()):
			return True
	return False

def check_duration(status):
	for path in status.keys():
		duration = status[path].duration()
		if duration is not None and duration > MAX_FILEOP_DURATION:
			status[path].warn('long_operation', 'operation took %s (%s to %s)'
					% (duration, status[path].start, status[path].end))

def merge_status(status_manifest, status_fileops, virtual_start_time,
		real_start_time, virtual_stop_time, real_stop_time):
	check_duration(status_manifest)
	check_duration(status_fileops)
	paths = { p
			for p in set(status_manifest.keys()) | set(status_fileops.keys())
			if not is_windows_junk(p) }

	delta_stats = Stats()
	duration_stats = Stats()
	status = { path: merge_tracking_status(status_manifest.get(path),
					status_fileops.get(path), delta_stats, duration_stats)
			for path in paths}

	for path, tracking in status.items():
		if tracking.end is None:
			continue
		if tracking.end > virtual_stop_time:
			tracking.warn('impossible_timestamp',
					'operation at %f after nominal timeout at %f'
					% (tracking.time(), virtual_stop_time.timestamp()))
		elif virtual_stop_time - tracking.end < TIMEOUT_MARGIN:
			tracking.warn('timeout_margin',
					'operation at %f too close before timeout %f'
					% (tracking.time(), virtual_stop_time.timestamp()))

	last_operation = max(status[path].end for path in paths
			if status[path].end is not None)
	return status, delta_stats, duration_stats, last_operation
