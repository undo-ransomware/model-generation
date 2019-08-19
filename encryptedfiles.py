import io
import os
import sys
import json

basedir = sys.argv[1]
outdir = sys.argv[2]
for task in sys.argv[3:]:
	analysis = os.path.join(basedir, task)
	with io.open(os.path.join(analysis, 'undumped.json'), 'rb') as filelog:
		for line in filelog:
			data = json.loads(line)
			path = data['path']
			if path is None:
				continue

			filename = os.path.basename(path)
			# FIXME should preserve the original name here
			targetDir = os.path.join(outdir, task)
			if not os.path.isdir(targetDir):
				os.mkdir(targetDir)
			target = os.path.join(outdir, task, filename)
			if not os.path.isfile(target):
				os.link(os.path.join(analysis, path), target)
			# FIXME should write a log os fileops, too
	print(task)
