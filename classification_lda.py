import numpy as np
import simpledataset
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis

# training set size doesn't really matter; 90% and 1% behave almost identically
x_train, x_test, y_train, y_test = simpledataset.get_data(test_size=0.1)

# find the best features
lda = LinearDiscriminantAnalysis()
lda.fit(x_train, y_train)
weights, bias = lda.coef_, lda.intercept_
acc_train = lda.score(x_test, y_test)
acc_test = lda.score(x_test, y_test)
print('accuracy: train=%8.5f test=%8.5f' % (acc_train, acc_test))

# write in a format that visualizer_linear.py can plot
compat_weights = np.concatenate((weights, -weights), axis=0)
compat_bias = np.concatenate((bias, -bias), axis=0)
np.savez_compressed('classification_lda', features=compat_weights, biases=compat_bias)
