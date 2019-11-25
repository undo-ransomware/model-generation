#!/usr/bin/python3
import io
import os
import requests
import json

# downloading these using the GitHub web interface is silly, but so is cloning
# the 500MB repository for two 10kb files.
MIMEBASE = 'https://raw.githubusercontent.com/nextcloud/server/master/resources/config/'
MIMEMAP = 'mimetypemapping.dist.json'
MIMEALIAS = 'mimetypealiases.dist.json'

def loadncjson(name):
	if not os.path.isfile(name):
		with io.open(name, 'w', encoding='utf-8') as outfile:
			outfile.write(requests.get(MIMEBASE + name).text)
	with io.open(name, 'rb') as infile:
		return json.load(infile)

mimemap = loadncjson(MIMEMAP)
mimealias = loadncjson(MIMEALIAS)

def ncmime(path):
	'''get mime type that NextCloud would assign based on file extension'''
	
	if os.path.isdir(path):
		return 'httpd/unix-directory'
	basename, ext = os.path.splitext(path)
	if ext == '' or ext[1:] not in mimemap:
		return 'application/octet-stream'
	# sometimes there are additional, more generic mimetypes. only use the most
	# specific one.
	return mimemap[ext[1:]][0]
