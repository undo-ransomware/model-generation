#include <math.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#define BUFSZ (1024*1024)

struct table {
	float byteent[256];
	float *result;
};
struct state {
	int blocksize;
	int n_tables;
	size_t nblocks;
	size_t nalloc;
	size_t size;
	float *within_block;
	float *rel_to_file;
	float byteent[256];
	uint8_t buffer[BUFSZ];
	struct table tables[0];
};

struct state *fe_alloc(int blocksize, int n_tables) {
	struct state *st = malloc(sizeof(struct state) + n_tables * sizeof(struct table));
	assert(st);
	st->blocksize = blocksize;
	st->n_tables = n_tables;
	st->nalloc = 0;
	assert(BUFSZ % blocksize == 0);
	st->within_block = NULL;
	st->rel_to_file = NULL;
	for (int i = 0; i < st->n_tables; i++)
		st->tables[i].result = NULL;
	return st;
}

void fe_free(struct state *st) {
	free(st->within_block);
	free(st->rel_to_file);
	for (int i = 0; i < st->n_tables; i++)
		free(st->tables[i].result);
	free(st);
}

#define SAFE_REALLOC(ptr, size) \
	do { \
		ptr = realloc(ptr, size); \
		assert(ptr); \
	} while (0)

size_t fe_prepare(struct state *st, size_t size, ...) {
	size_t nblocks = (size + st->blocksize - 1) / st->blocksize;
	if (nblocks > st->nalloc) {
		SAFE_REALLOC(st->within_block, nblocks * sizeof(float));
		SAFE_REALLOC(st->rel_to_file, nblocks * sizeof(float));
		for (int i = 0; i < st->n_tables; i++)
			SAFE_REALLOC(st->tables[i].result, nblocks * sizeof(float));
		st->nalloc = nblocks;
	}
	st->nblocks = nblocks;
	st->size = size;

	va_list tables;
	va_start(tables, size);
	for (int i = 0; i < st->n_tables; i++)
		memcpy(st->tables[i].byteent, va_arg(tables, float*), sizeof(st->tables[i].byteent));
	assert(va_arg(tables, float*) == NULL);
	va_end(tables);

	return nblocks;
}

static float entropy(size_t counts[256], float byteent[256], size_t total) {
	float entropy = 0;
	for (int b = 0; b < 256; b++)
		entropy += byteent[b] * counts[b];
	return entropy / total;
}

ssize_t fe_calculate(struct state *st, char *filename) {
	FILE *fp = fopen(filename, "rb");
	if (!fp)
		return -ENOENT;
	size_t nbytes = 0;
	size_t counts[256];
	memset(counts, 0, sizeof(counts));
	while (!feof(fp)) {
		size_t len = fread(st->buffer, 1, st->blocksize, fp);
		for (size_t i = 0; i < len; i++)
			counts[st->buffer[i]]++;
		nbytes += len;
	}
	for (int i = 0; i < 256; i++)
		if (counts[i] > 0)
			st->byteent[i] = -log2f(counts[i] / (float) nbytes);
		else
			// pretend that the byte would have been seen exactly once in twice
			// as much data. this is an upper limit to its frequency (and a
			// lower limit to its entropy): we didn't see it, so it's frequency
			// is <0.5 times per nbytes.
			st->byteent[i] = -log2f(.5f / nbytes);
	fclose(fp);
	if (nbytes != st->size)
		return -EINVAL;

	fp = fopen(filename, "rb");
	if (!fp)
		return -ENOENT;
	nbytes = 0;
	size_t block = 0;
	while (!feof(fp)) {
		size_t len = fread(st->buffer, 1, st->blocksize, fp);
		size_t blocks = (len + st->blocksize - 1) / st->blocksize;
		for (size_t j = 0; j < blocks; j++) {
			size_t bytes = len - st->blocksize * j;
			if (bytes > st->blocksize)
				bytes = st->blocksize;
			memset(counts, 0, sizeof(counts));
			for (size_t i = 0; i < bytes; i++)
				counts[st->buffer[j + i]]++;

			float ent = 0;
			for (int i = 0; i < 256; i++)
				if (counts[i] > 0)
					ent += log2f(counts[i] / (float) bytes) * counts[i];
			st->within_block[block] = -ent / bytes;
			st->rel_to_file[block] = entropy(counts, st->byteent, bytes);
			for (int i = 0; i < st->n_tables; i++)
				st->tables[i].result[block] = entropy(counts, st->tables[i].byteent, bytes);
			block++;
		}
		nbytes += len;
	}
	fclose(fp);
	if (nbytes != st->size)
		return -EINVAL;

	return 0;
}

void fe_get_byteent(struct state *st, float byteent[256]) {
	memcpy(byteent, st->byteent, sizeof(st->byteent));
}

void fe_get_sequences(struct state *st, float *within_block, float *rel_to_file, ...) {
	assert(within_block);
	assert(rel_to_file);
	memcpy(within_block, st->within_block, st->nblocks * sizeof(float));
	memcpy(rel_to_file, st->rel_to_file, st->nblocks * sizeof(float));

	va_list tables;
	va_start(tables, rel_to_file);
	for (int i = 0; i < st->n_tables; i++) {
		float *tab = va_arg(tables, float*);
		assert(tab);
		memcpy(tab, st->tables[i].result, st->nblocks * sizeof(float));
	}
	assert(va_arg(tables, float*) == NULL);
	va_end(tables);
}
