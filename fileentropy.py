import io
import json
from ctypes import *

fe = CDLL('./libfileentropy.so')
fe.fe_alloc.restype = c_void_p
fe.fe_alloc.argtypes = [c_int, c_int]
fe.fe_free.argtypes = [c_void_p]
fe.fe_count_bytes.restype = c_ssize_t
fe.fe_get_bytecounts.restype = POINTER(c_size_t)
fe.fe_get_byteent.argtypes = [c_void_p, c_float * 256]
fe.fe_get_within_block.restype = fe.fe_get_rel_to_file.restype = POINTER(c_float)
fe.fe_get_within_block.argtypes = fe.fe_get_rel_to_file.argtypes = [c_void_p]
fe.fe_get_sequence.restype = POINTER(c_float)
fe.fe_get_sequence.argtypes = [c_void_p, c_int]

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

def tolist(pointer, n_entries):
	return [pointer[i] for i in range(n_entries)]

class FileEntropy:
	def __init__(self, blocksize, *baselines):
		self.baselines = [Baseline(b) for b in baselines]
		self.st = c_void_p(fe.fe_alloc(blocksize, len(baselines)))

	def __del__(self):
		fe.fe_free(self.st)

	def count_bytes(self, filename):
		size = fe.fe_count_bytes(self.st, filename.encode('utf-8'))
		if size < 0:
			raise OSError('errno = %d' % err)
		counts = fe.fe_get_bytecounts(self.st)
		return { b: counts[b] for b in range(256) }

	def calculate(self, filename, *mime):
		size = fe.fe_count_bytes(self.st, filename.encode('utf-8'))
		if size < 0:
			raise OSError('errno = %d' % err)
		byteent = (c_float * 256)()
		fe.fe_get_byteent(self.st, byteent)

		assert len(mime) == len(self.baselines)
		baselines = [self.baselines[i][mime[i]] for i in range(len(mime))]
		nblocks = fe.fe_calculate_entropies(self.st,
				c_char_p(filename.encode('utf-8')), *baselines, None)
		if nblocks < 0:
			raise OSError('errno = %d' % nblocks)
		within_block = tolist(fe.fe_get_within_block(self.st), nblocks)
		rel_to_file = tolist(fe.fe_get_rel_to_file(self.st), nblocks)
		seqs = [tolist(fe.fe_get_sequence(self.st, i), nblocks)
				for i in range(len(mime))]
		return (size, list(byteent), within_block, rel_to_file, *seqs)
