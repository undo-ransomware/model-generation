import tensorflow.compat.v1 as tf
import numpy as np
import io
import json
from sklearn.model_selection import train_test_split

blob = np.load('simplefeatures.npz')
classes = blob['classes']
features = blob['features']
byte_entropies = blob['byte_entropies']
with io.open('simplefeatures.headers.json', 'r') as infile:
	headers = json.load(infile)
nclasses = 2
data = np.concatenate((features, byte_entropies), axis=1)
nfeatures = len(data[0])

# subdivide into training and testing data
x_train, x_test, y_train, y_test = train_test_split(data, classes, test_size=0.2)

# linear classifier: y = Wx + b
x = tf.placeholder(tf.float32, [None, nfeatures])
y_in = tf.placeholder(tf.int64, [None])
W = tf.get_variable('W', [nfeatures, nclasses],
		initializer=tf.initializers.lecun_uniform())
b = tf.get_variable('b', [nclasses], initializer = tf.initializers.constant(0.0))
y_pred = tf.add(tf.matmul(x, W), b)

# loss function and optimizer (black voodoo magic)
# more L2 loss for the weights helps convergence, but tends to shift optimization
# towards uniform weights, which doesn't exactly help accuracy.
loss = tf.losses.sparse_softmax_cross_entropy(y_in, y_pred) + 1e-5 * tf.nn.l2_loss(W)
train_step = tf.train.AdamOptimizer(1e-3).minimize(loss)

# summaries for tensorboard
label_pred = tf.argmax(y_pred, 1)
accuracy = tf.reduce_mean(tf.cast(tf.equal(label_pred, y_in), tf.float32))
train_acc = tf.summary.scalar('train_acc', accuracy)
test_acc = tf.summary.scalar('test_acc', accuracy)
train_loss = tf.summary.scalar('train_loss', loss)
test_loss = tf.summary.scalar('test_loss', loss)
train_summaries = tf.summary.merge([train_loss, train_acc])
test_summaries = tf.summary.merge([test_loss, test_acc])

# now pretend there is no such thing as LDA and traing this as if it was a DNN:
# iterate for "enough" iterations, for some unknown value of "enough".
# unsurprisingly, it takes forever to converge.
# surprisingly, it does so at 82%...
sess = tf.InteractiveSession()
writer = tf.summary.FileWriter('tflog', sess.graph)
sess.run(tf.global_variables_initializer())
for i in np.arange(0, 10000):
	# train
	_, cost_train, acc_train, train_summary = sess.run(
			[train_step, loss, accuracy, train_summaries],
			feed_dict={ x: x_train, y_in: y_train })
	writer.add_summary(train_summary, i)
	
	# test
	cost_test, acc_test, test_summary = sess.run(
			[loss, accuracy, test_summaries],
			feed_dict={ x: x_test, y_in: y_test })
	writer.add_summary(test_summary, i)
	
	print('epoch %4i  train: loss=%8.3f acc=%6.5f  test: loss=%8.3f acc=%6.5f' %
			(i, cost_train, acc_train, cost_test, acc_test))

weights, bias = sess.run([W, b])
np.savez_compressed('classification_linear', features=weights, biases=bias)
