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
	size_t counts[256];
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

ssize_t fe_count_bytes(struct state *st, char *filename) {
	FILE *fp = fopen(filename, "rb");
	if (!fp)
		return -ENOENT;
	size_t nbytes = 0;
	memset(st->counts, 0, sizeof(st->counts));
	while (!feof(fp)) {
		size_t len = fread(st->buffer, 1, st->blocksize, fp);
		for (size_t i = 0; i < len; i++)
			st->counts[st->buffer[i]]++;
		nbytes += len;
	}
	fclose(fp);
	st->size = nbytes;
	return nbytes;
}

size_t *fe_get_bytecounts(struct state *st) {
	return st->counts;
}

void fe_get_byteent(struct state *st, float byteent[256]) {
	size_t nbytes = 0;
	for (int i = 0; i < 256; i++)
		nbytes += st->counts[i];

	for (int i = 0; i < 256; i++)
		if (st->counts[i] > 0)
			byteent[i] = -log2f(st->counts[i] / (float) nbytes);
		else
			// pretend that the byte would have been seen exactly once in twice
			// as much data. this is an upper limit to its frequency (and a
			// lower limit to its entropy): we didn't see it, so it's frequency
			// is <0.5 times per nbytes.
			byteent[i] = -log2f(.5f / nbytes);
}

static float entropy(size_t counts[256], float byteent[256], size_t total) {
	float entropy = 0;
	for (int b = 0; b < 256; b++)
		entropy += byteent[b] * counts[b];
	return entropy / total;
}

#define SAFE_REALLOC(ptr, size) \
	do { \
		ptr = realloc(ptr, size); \
		assert(ptr); \
	} while (0)
ssize_t fe_calculate_entropies(struct state *st, char *filename, ...) {
	size_t nblocks = (st->size + st->blocksize - 1) / st->blocksize;
	if (nblocks > st->nalloc) {
		SAFE_REALLOC(st->within_block, nblocks * sizeof(float));
		SAFE_REALLOC(st->rel_to_file, nblocks * sizeof(float));
		for (int i = 0; i < st->n_tables; i++)
			SAFE_REALLOC(st->tables[i].result, nblocks * sizeof(float));
		st->nalloc = nblocks;
	}
	st->nblocks = nblocks;

	va_list tables;
	va_start(tables, filename);
	for (int i = 0; i < st->n_tables; i++)
		memcpy(st->tables[i].byteent, va_arg(tables, float*), sizeof(st->tables[i].byteent));
	assert(va_arg(tables, float*) == NULL);
	va_end(tables);

	float byteent[256];
	fe_get_byteent(st, byteent);

	FILE *fp = fopen(filename, "rb");
	if (!fp)
		return -ENOENT;
	size_t nbytes = 0;
	size_t block = 0;
	size_t counts[256];
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
			st->rel_to_file[block] = entropy(counts, byteent, bytes);
			for (int i = 0; i < st->n_tables; i++)
				st->tables[i].result[block] = entropy(counts, st->tables[i].byteent, bytes);
			block++;
		}
		nbytes += len;
	}
	fclose(fp);

	if (nbytes != st->size)
		return -EINVAL;
	return nblocks;
}

float *fe_get_within_block(struct state *st) {
	return st->within_block;
}

float *fe_get_rel_to_file(struct state *st) {
	return st->rel_to_file;
}

float *fe_get_sequence(struct state *st, int tab) {
	assert(tab < st->n_tables);
	return st->tables[tab].result;
}
