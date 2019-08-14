#!/usr/bin/python3
import io
import json
import numpy as np
import matplotlib.pyplot as pyplot
from collections import Counter
from matplotlib.backends.backend_pdf import PdfPages

def plot(entropy, mime, pdf):
	pyplot.figure(figsize=(12, 10))
	pyplot.ylabel('entropy')
	pyplot.xlabel('byte value')
	pyplot.title('Entropy distribution for ' + mime)
	pyplot.bar(np.arange(256), entropy, 1.15)
	pdf.savefig()
	pyplot.close()

for base in 'nc', 'magic':
	with io.open(base + 'baseline.json', 'r') as infile:
		data = json.load(infile)
	with PdfPages(base + '.pdf') as pdf:
		for mime, stats in data.items():
			plot(stats, mime, pdf)
