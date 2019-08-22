import numpy as np
import simpledataset
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from sklearn.model_selection import train_test_split
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis

features, classes = simpledataset.get_data(entropies=True)
meta = simpledataset.get_metadata()
headers = simpledataset.get_headers(entropies=True)

test_size=0.2

def analyze(mime, selected, pdf):
	feats = np.take(features, selected, axis=0)
	labels = np.take(classes, selected, axis=0)
	x_train, x_test, y_train, y_test = train_test_split(feats, labels,
			test_size=test_size, shuffle=True)
	print("%s: train %d, test %d" % (mime, len(x_train), len(x_test)))

	prior_train = np.mean(y_train)
	prior_test = np.mean(y_test)
	if prior_train > 0.999 or prior_test < 0.001:
		print('    guess by priors: train=%8.5f test=%8.5f' % (prior_train, prior_test))
		weights = np.zeros(len(headers))
		bias = prior_train
		if prior_train < 0.5:
			acc_train = 1 - prior_train
			acc_test = 1 - prior_test
		else:
			acc_train = prior_train
			acc_test = prior_test
	else:
		# find the best features
		lda = LinearDiscriminantAnalysis()
		lda.fit(x_train, y_train)
		weights, bias = lda.coef_[0], lda.intercept_[0]
		acc_train = lda.score(x_test, y_test)
		acc_test = lda.score(x_test, y_test)
		data[mime + '.weights'] = weights
		data[mime + '.bias'] = bias
	stats = 'train %d=%8.5f/%8.5f test %d=%8.5f/%8.5f' % (len(x_train), acc_train,
			prior_train, len(x_test), acc_test, prior_test)
	print('    accuracy: %s' % stats)

	wts = sorted(((weights[i], headers[i]) for i in range(len(headers))),
			key=lambda tuple: abs(tuple[0]), reverse=True)
	cutoff = np.sum(np.abs(weights)) * 1e-3
	wts = [tuple for tuple in wts if abs(tuple[0]) > cutoff]
	plt.figure(figsize=(13, 8))
	# plt.xlabel('indicative of class 0 (good)')
	# plt.ylabel('indicative of class 1 (encrypted)')
	plt.title('%s: %s' % (mime, stats))
	x = weights[0]
	y = -x
	bars = plt.bar(range(len(wts)), [weight for weight, name in wts], 0.8,
		color='#cccccc')
	plt.xticks([], [])
	for i in range(len(wts)):
		weight, name = wts[i]
		rect = bars[i]
		rot = 'bottom' if weight > 0 else 'top'
		height = rect.get_height()
		plt.text(rect.get_x() + rect.get_width() / 2.0, 0, name,
				ha='center', va=rot, rotation=90, size=7)
	pdf.savefig()
	plt.close()

	return acc_train * len(x_train), acc_test * len(x_test)

mimes = [sample['mime.byext'] for sample in meta]
data = dict()
with PdfPages('linear.pdf') as pdf:
	analyze('all', range(len(mimes)), pdf)
	acc_train = acc_test = 0
	other = []
	for mime in set(mimes):
		selected = [index for index in range(len(mimes)) if mimes[index] == mime]
		if len(selected) > len(headers):
			atrain, atest = analyze(mime, selected, pdf)
			acc_train += atrain
			acc_test += atest
		else:
			# less variables than observations. breaks any linear algebra.
			other += selected
	atrain, atest = analyze('other', other, pdf)
	acc_train = (acc_train + atrain) / len(mimes) / (1 - test_size)
	acc_test = (acc_test + atest) / len(mimes) / test_size
	print('overall stats: train=%8.5f test=%8.5f' % (acc_train, acc_test))

np.savez_compressed('classification_lda', **data)
