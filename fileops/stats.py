from math import sqrt, nan, inf

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
