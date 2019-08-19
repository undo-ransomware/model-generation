features = read.csv("pcaplot.tmp", sep="\t", header=TRUE);
mimes = factor(features$mime.byext)
classes = features$class
features$class = NULL
features$mime.byext = mimes

featureNames = names(features);
dim(features);

# do PCA
scaled.features = scale(features);
pca = princomp(scaled.features, cor=T);
x = pca$scores[,1]
y = pca$scores[,2]
xsd = pca$sdev[1]
ysd = pca$sdev[2]
xv = pca$loadings[,1]
yv = pca$loadings[,2]

W = 12
H = 10
# this is a horrible palette, but there's no good ones for >10 features anyway.
palette(c(rgb(0,0,0,.1), 'green', 'red', rgb(0,0,1,.1)))

# make a PDF of the corrent aspect ratio
pdf("pcascatter1.pdf", width=W, height=W*ysd/xsd);
par(cex=0.4, mar=c(0,0,0,0));
# plot feature vectors
plot(xv, yv, type="n", ann=F, frame.plot=F, axes=F);
arrows(x0=0, y0=0, x1=xv, y1=yv, length=.1, col="gray");
# plot file positions
par(new=TRUE);
plot(x, y, type="n", ann=F, frame.plot=T, axes=F);
points(x, y, col=classes, pch='.');
#legend('topright', legend=levels(mimes), col=classes, pch='.')
# plot feature names on top
par(new=TRUE);
plot(xv, yv, type="n", ann=F, frame.plot=F, axes=F);
text(x=xv, y=yv, labels=featureNames, col='red');
# add a plot title
par(cex=0.4, mar=c(0,0,2.5,0));
dev.off()

pdf("pcascatter2.pdf", width=W, height=H);
par(cex=0.4, mar=c(0,0,0,0));
# plot distribution of variance
max = max(pca$sdev);
sdev = pca$sdev[pca$sdev >= max / 10000];
par(cex=.6, mar=c(5,5,4,1));
selected = rep("black", times=length(sdev));
selected[1:2] = hsv(h=0/3, s=3/3, v=1);
plot(sdev, xlab="component", ylab="variance", xlim=c(1, length(sdev)),
	col=selected, xaxt="n", main="variance per component")
ticks = seq(from=1, to=length(sdev), by=1);
axis(1, at=ticks, tick=TRUE, crt=1);
dev.off()
