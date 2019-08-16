import io
import json
from ctypes import *

fe = CDLL('./libfileentropy.so')
fe.fe_alloc.restype = c_void_p
fe.fe_alloc.argtypes = [c_int, c_int]
fe.fe_free.argtypes = [c_void_p]
fe.fe_prepare.restype = c_size_t
fe.fe_calculate.argtypes = [c_void_p, c_char_p]
fe.fe_get_byteent.argtypes = [c_void_p, c_float * 256]

class Baseline:
	def __init__(self, baselines):
		self.baselines = baselines
		self.cache = dict()

	def __getitem__(self, key):
		if key not in self.cache:
			byteent = self.baselines[key]
			cpb = (c_float * 256)()
			for i in range(256):
				cpb[i] = byteent[i]
			self.cache[key] = cpb
		return self.cache[key]

class FileEntropy:
	def __init__(self, blocksize, *baselines):
		self.baselines = [Baseline(b) for b in baselines]
		self.st = c_void_p(fe.fe_alloc(blocksize, len(baselines)))

	def __del__(self):
		fe.fe_free(self.st)

	def calculate(self, filename, size, *mime):
		assert len(mime) == len(self.baselines)
		baselines = [self.baselines[i][mime[i]] for i in range(len(mime))]
		blocks = fe.fe_prepare(self.st, size, *baselines, None)
		err = fe.fe_calculate(self.st, filename.encode('utf-8'))
		if err != 0:
			raise OSError('error %d' % err)
		byteent = (c_float * 256)()
		fe.fe_get_byteent(self.st, byteent)
		byteent = [byteent[i] for i in range(256)]
		seqs = [(c_float * blocks)() for i in range(len(mime) + 2)]
		fe.fe_get_sequences(self.st, *seqs, None)
		rel = ([seq[i] for i in range(blocks)] for seq in seqs)
		return (byteent, *rel)
