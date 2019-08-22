import numpy as np
import io
import sys
import json
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

blob = np.load(sys.argv[1])
weights = blob['features']
bias = blob['biases']
with io.open('simplefeatures.headers.json', 'r') as infile:
	headers = json.load(infile)
features = headers + ['entropy.byte_%02x' % i for i in range(256)]

with PdfPages('linear.pdf') as pdf:
	plt.figure(figsize=(12, 10))
	plt.xlabel('indicative of class 0 (good)')
	plt.ylabel('indicative of class 1 (encrypted)')
	plt.title('feature weights for linear classification')
	x = weights[0]
	y = [-_ for _ in x]
	plt.scatter(x, y)
	for i in range(len(weights[0])):
		plt.text(x[i], y[i], features[i])
	pdf.savefig()
	plt.close()
