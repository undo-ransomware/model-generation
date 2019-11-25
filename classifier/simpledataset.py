import numpy as np
import io
import json

_blob = None
_headers = None
_info = None

def _load_data():
	global _blob
	if _blob is None:
		_blob = np.load('simplefeatures.npz')
def _load_headers():
	global _headers
	if _headers is None:
		with io.open('simplefeatures.headers.json', 'r') as infile:
			_headers = json.load(infile)
def _load_infos():
	global _info
	if _info is None:
		with io.open('simplefeatures.info.json', 'r') as infile:
			_info = json.load(infile)

def get_headers(features=True, entropies=True):
	_load_headers()
	heads = []
	if features:
		heads += _headers
	if entropies:
		heads += ['entropy.byte_%02x' % i for i in range(256)]
	return heads

def get_data(features=True, entropies=True):
	_load_data()
	feats = []
	if features:
		feats.append(_blob['features'])
	if entropies:
		feats.append(_blob['byte_entropies'])
	feats = np.concatenate(feats, axis=1)
	return (feats, _blob['classes'])

def get_metadata():
	_load_infos()
	return _info
