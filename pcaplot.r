features = read.csv("pcaplot.tmp", sep="\t", header=TRUE);
mimes = factor(features$mime.libmagic)
classes = features$class
features$class = NULL
features$mime.libmagic = NULL

featureNames = names(features);
dim(features);

# do PCA
scaled.features = scale(features);
pca = princomp(scaled.features, cor=FALSE);
x = pca$scores[,1]
y = pca$scores[,2]
xsd = pca$sdev[1]
ysd = pca$sdev[2]
xv = pca$loadings[,1]
yv = pca$loadings[,2]

W = 12
H = 10
palette(rainbow(length(levels(mimes))))

# make a PDF of the corrent aspect ratio
pdf("pcascatter1.pdf", width=W, height=W*ysd/xsd);
par(cex=0.4, mar=c(0,0,0,0));
# plot text positions
plot(x, y, type="n", ann=FALSE, frame.plot=TRUE, axes=FALSE);
points(x, y, pch='.', col=mimes);
legend('topright', legend=levels(mimes), col=1:length(levels(mimes)), pch='.')
# plot feature vectors
par(new=TRUE);
plot(xv, yv, type="n", ann=FALSE, frame.plot=FALSE, axes=FALSE);
arrows(x0=0, y0=0, x1=xv, y1=yv, length=.1, col="gray");
# plot feature names on top
text(x=xv, y=yv, labels=featureNames, col=hsv(h=0/3, s=3/3, v=1));
# add a plot title
par(cex=0.4, mar=c(0,0,2.5,0));
title(main="first two components");
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
