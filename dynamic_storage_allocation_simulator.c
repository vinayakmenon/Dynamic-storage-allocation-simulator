/*
 * Dynamic storage allocation algorithm simulator
 *
 * The idea is to capture a "pattern file" from a
 * device which contains the allocation patter including
 * time and size. The pattern file is used by this
 * simulator as input to various storage allocation algos.
 * The user can view the behaviour.
 *
 * Author: Vinayak Menon <vinayakm.list@gmail.com>
 *
 * Version: This is a work in progress. This program will
 * soon rewritten in perl.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/queue.h>

#define PATTERN_FILE_LINE_LENGTH	100
#define MAX_ALLOC_SIZES_SUPPORTED	7000

#define DEBUG_MASK 0xFFFFFFFF

#define print_dsas(debug_level, args...)	\
	do {					\
		if (DEBUG_MASK & debug_level) { \
			printf(args);		\
		}				\
	} while(0)

int ff_flag = 0, bf_flag = 0, df_flag = 0;
unsigned int repeat_count = 0;
unsigned int max_allocation_size = 0;
unsigned int max_num_alloc_sizes = 0;

struct memory_area {
	unsigned int *bitmap;
	unsigned int count;
	unsigned int mem_size; //in bytes
	unsigned int granularity; // in bytes
	unsigned int bitmap_size;
} mem_area;

const char* pattern_file = NULL;
FILE* pattern_fp;

struct alloc_struct {
	unsigned int offset;
	LIST_ENTRY(alloc_struct) alloc_ptr;
};

struct alloc_list {
	unsigned int size;
	struct alloc_struct* last_e;
	unsigned int length;
	LIST_HEAD(alloc_head, alloc_struct)  allocation_head;
} *alloc_list_ptr;

unsigned int alloc_list_size = 0;

static void call_pattern_file_parser();
static void start_alloc_or_free(int alloc, unsigned int size);
static int call_simulators(int alloc, unsigned int size, int offset);
static int add_to_alloc_list(int offset, unsigned int size);
static int retrieve_from_list(unsigned int size);
static int init_alloc_lists(void);
static struct alloc_struct *get_element_no(struct alloc_head* ah, int elem);
static struct alloc_struct *list_not_empty(struct alloc_head* ah);
static struct alloc_list* get_alloc_ptr_of_size(unsigned int size);
static void call_first_fit(int alloc, unsigned int size, int offset);

void help (void)
{
	printf("Usage:\n");
	printf("dsas [-s size] [-f] [-b] [-d] [-h] [-g granularity]\n");
	printf("s --> total size of memory area in bytes\n");
	printf("f --> Run first fit algorithm\n");
	printf("b --> Run best fit algorithm\n");
	printf("d --> Run distributed fit algorithm\n");
	printf("g --> minimum granularity of allocation\n");
	printf("i --> Path to the pattern file\n");
	printf("r --> The number of times pattern has to be repeated if EOF of pattern file is reached\n");
	printf("m --> maximum allocation size in bytes\n");
	printf("n --> maximum number of different allocation sizes in the pattern\n");
	printf("h --> help\n");
}

int main(int argc, char **argv)
{
	int opt;
	while ((opt = getopt(argc, argv, "hfbds:g:i:r:m:n:")) != -1) {
		
		switch(opt) {
			case 'h':
				help();
				return 0;
			case 'f':
				ff_flag = 1;
				break;
			case 'b':
				bf_flag = 1;
				break;
			case 'd':
				df_flag = 1;
				break;
			case 's':
				mem_area.mem_size = strtoul(optarg, NULL, 0);
				break;
			case 'g':
				mem_area.granularity = strtoul(optarg, NULL, 0);
				break;
			case 'i':
				pattern_file = optarg;
				break;
			case 'r':
				repeat_count = strtoul(optarg, NULL, 0);
				break;
			case 'm':
				max_allocation_size = strtoul(optarg, NULL, 0);
				break;
			case 'n':
				max_num_alloc_sizes = strtoul(optarg, NULL, 0);
				break;
			case '?':
				help();
				return -1;
			default:
				help();
				return -1;
		}
	}		
	
	if (!ff_flag && !bf_flag && !df_flag)
		ff_flag = bf_flag = df_flag = 1; //run all algos

	if (!mem_area.mem_size) {
		print_dsas(1,"error:Input proper memory size\n");
		help();
		return -1;
	}

	if (!mem_area.granularity) {
		print_dsas(1,"error:Input proper granularity\n");
		help();
		return -1;
	}

	if (!pattern_file) {
		print_dsas(1,"error:Input proper pattern file\n");
		help();
		return -1;
	}

	if (!max_allocation_size) {
		print_dsas(1,"error:Input non zero max allocation size\n");
		help();
		return -1;
	}

	if (max_allocation_size < mem_area.granularity) {
		print_dsas(1,"error:max allocation size less than granularity\n");
		return -1;
	}

	if (max_allocation_size > mem_area.mem_size) {
		print_dsas(1,"error:max allocation size greater than memory size\n");
		return -1;
	}

	print_dsas(4,"Memory Size:%ld bytes\n", mem_area.mem_size);
	print_dsas(4,"Granularity:%ld bytes\n", mem_area.granularity);
	print_dsas(4,"Pattern file location:%s\n", pattern_file);
	print_dsas(4,"Repeat count:%ld\n", repeat_count);
	print_dsas(4,"Max allocation size:%ld\n", max_allocation_size);

	if (!max_num_alloc_sizes) {
		max_num_alloc_sizes = MAX_ALLOC_SIZES_SUPPORTED;
		print_dsas(4,"Maximum num of alloc sizes supported:%ld (default)\n", MAX_ALLOC_SIZES_SUPPORTED);
	} else {
		print_dsas(4,"Maximum num of alloc sizes supported:%ld\n", max_num_alloc_sizes);
	}

	mem_area.bitmap_size = (mem_area.mem_size)/(8 * mem_area.granularity);

	print_dsas(4,"Bitmap size:%ld bytes\n", mem_area.bitmap_size);

	mem_area.bitmap = (unsigned int*) calloc(1, mem_area.bitmap_size);
	if (!mem_area.bitmap) {
		print_dsas(1,"Failed to allocate memory for bitmap\n");
		return -1;
	}

	mem_area.count = mem_area.mem_size/mem_area.granularity;

	print_dsas(4,"Bitmap count:%ld granules\n", mem_area.count);

	/* The pattern file should be in the following
         * format.
	 * 1,[count in terms of granularity]
	 * 0,[coun tin terms of granularity]
	 * ....
	 * 1 indicates an allocation
	 * and 0 indicates a free.
	 */

	pattern_fp = fopen(pattern_file, "r");
	if (!pattern_fp) {
		print_dsas(1,"error opening the pattern file:%s\n", strerror(errno));
		goto end;
	}

	if (init_alloc_lists()) {
		print_dsas(1,"error: failed to init alloc lists\n");
		goto end;
	}

	call_pattern_file_parser();

end:
	free(mem_area.bitmap);
	fclose(pattern_fp);

	return 0;	
}

void call_pattern_file_parser(void)
{
	int alloc = 0;
	unsigned int size = 0; //in bytes
	char* orig_line;
	char* c;
	unsigned int line_number = 0;

	char *line = malloc(PATTERN_FILE_LINE_LENGTH);
	if (!line) {
		print_dsas(1,"%s:Error allocating memory", __func__);
		return;
	}

	orig_line = line;

	while(!feof(pattern_fp)) {
		if (fgets(line, PATTERN_FILE_LINE_LENGTH - 1, pattern_fp)) {
			line_number++;
			if ((line[0] == '\n') || (line[0] == ' ') ||(line[0] == '\t'))
				continue;

			if ((c = strtok(line, ","))) {
				alloc = atoi(c);
				if ((alloc != 1) && (alloc != 0)) {
					print_dsas(1,"Wrong val in pattern file:alloc %d, line:%ld\n", alloc, line_number);
					goto end;
				}
				if ((c = strtok(NULL, ","))) {
					size = strtoul(c, NULL, 0);
					if (size < mem_area.granularity) {
						print_dsas(1,"error:Size less than granularity: line: %ld\n", line_number);
						goto end;
					} else if (size > max_allocation_size) {
						print_dsas(1,"error: size > max allocation size: line: %ld\n", line_number);
						goto end;
					}					
				} else {
					print_dsas(1,"error: Parsing the pattern file: size, line:%ld\n", line_number);
					goto end;
				}
				line = orig_line;
				start_alloc_or_free(alloc, size);
			} else {
				print_dsas(1,"Error parsing pattern file:line:%ld\n", line_number);
				goto end;
			}					
		}
		alloc = size = 0;
	}
	line_number = 0;

end:
	free(orig_line);	
}

void start_alloc_or_free(int alloc, unsigned int size)
{
	int offset = 0;

	print_dsas(8,"alloc:%d,size:%ld\n", alloc, size);

	if (alloc) { //allocation
		offset = call_simulators(alloc, size, offset);
		if (offset < 0) {
			print_dsas(1,"Allocation failure:size:%ld\n", size);
			return;
		}

		print_dsas(8,"call_simulators returned offset:%ld\n", offset);
		if (add_to_alloc_list(offset, size)) {
			print_dsas(1,"Add to alloc list failed:%ld, %ld\n", offset, size);
			return;
		}
	} else { //free
		offset = retrieve_from_list(size);
		if (offset < 0) {
			print_dsas(1,"List retrieval failure:size:%ld\n", size);
			return;
		}
		call_simulators(alloc, size, offset);
	}
}

int call_simulators(int alloc, unsigned int size, int offset)
{
	if (alloc && (size > mem_area.count)) {
		print_dsas(1, "error: size > available in memory area\n");
		return -1;
	}

	if (ff_flag)
		call_first_fit(alloc, size, offset);
}

void call_first_fit(int alloc, unsigned int size, int offset)
{
	unsigned int granule_no;

	granule_no = bitmap_find_next_zero_area(mem_area.bitmap, mem_area.count, 0, size); 

	if (granule_no >= mem_area.count) {
		print_dsas(1, "Allocation failed for size:%ld", size);
		return;
	}
	bitmap_set(mem_area.bitmap, granule_no, size);
}

#define BITS_PER_INT 32
#define BITOP_WORD(nr)          ((nr) / BITS_PER_INT)
#define ffz(x) __builtin_ffs ( ~(x) )
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) % BITS_PER_INT))
#define BITMAP_LAST_WORD_MASK(nbits)                                    \
{									\
	((nbits) % BITS_PER_INT) ?                                     \
		(1UL<<((nbits) % BITS_PER_INT))-1 : ~0UL               \
}
void bitmap_set(unsigned long *map, int start, int nr)
{
	unsigned long *p = map + BITOP_WORD(start);
	const int size = start + nr;
	int bits_to_set = BITS_PER_INT - (start % BITS_PER_INT);
	unsigned long mask_to_set = BITMAP_FIRST_WORD_MASK(start);

	while (nr - bits_to_set >= 0) {
		*p |= mask_to_set;
		nr -= bits_to_set;
		bits_to_set = BITS_PER_INT;
		mask_to_set = ~0UL;
		p++;
	}
	if (nr) {
		mask_to_set &= BITMAP_LAST_WORD_MASK(size);
		*p |= mask_to_set;
	}
}

unsigned int find_next_bit(const unsigned int *addr, unsigned int size,
			    unsigned int offset)
{
	const unsigned int *p = addr + BITOP_WORD(offset);
	unsigned int result = offset & ~(BITS_PER_INT-1);
	unsigned int tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_INT;
	if (offset) {
		tmp = *(p++);
		tmp &= (~0UL << offset);
		if (size < BITS_PER_INT)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= BITS_PER_INT;
		result += BITS_PER_INT;
	}
	while (size & ~(BITS_PER_INT-1)) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_INT;
		size -= BITS_PER_INT;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp &= (~0UL >> (BITS_PER_INT - size));
	if (tmp == 0UL)
		return result + size;
found_middle:
	return result + __builtin_ffs(tmp);
}

unsigned int find_next_zero_bit(const unsigned int *addr, unsigned int size,
				 unsigned int offset)
{
	const unsigned int *p = addr + BITOP_WORD(offset);
	unsigned int result = offset & ~(BITS_PER_INT-1);
	unsigned int tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_INT;
	if (offset) {
		tmp = *(p++);
		tmp |= ~0UL >> (BITS_PER_INT - offset);
		if (size < BITS_PER_INT)
			goto found_first;
		if (~tmp)
			goto found_middle;
		size -= BITS_PER_INT;
		result += BITS_PER_INT;
	}
	while (size & ~(BITS_PER_INT-1)) {
		if (~(tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_INT;
		size -= BITS_PER_INT;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp |= ~0UL << size;
	if (tmp == ~0UL)
		return result + size;
found_middle:
	return result + ffz(tmp);
}

unsigned int bitmap_find_next_zero_area(unsigned int *map,
					 unsigned int size,
					 unsigned int start,
					 unsigned int nr)
{
	unsigned int index, end, i;
again:
	index = find_next_zero_bit(map, size, start);

	end = index + nr;
	if (end > size)
		return end;
	i = find_next_bit(map, end, index);
	if (i < end) {
		start = i + 1;
		goto again;
	}
	return index;
}

int add_to_alloc_list(int offset, unsigned int size)
{
	struct alloc_list* a_p_s;

	print_dsas(8,"%s:offset:%ld, size:%lu\n",__func__, offset, size);
	a_p_s = get_alloc_ptr_of_size(size);
	if (!a_p_s) {
		if (alloc_list_size > max_num_alloc_sizes) {
			print_dsas(1, "Alloc list size exceeded max_num_alloc_sizes\n");
			return -1;
		}
		a_p_s = (struct alloc_list*)(alloc_list_ptr + alloc_list_size);
		alloc_list_size++;
		a_p_s->size = size;
		LIST_INIT(&(a_p_s->allocation_head));
		struct alloc_struct* a = malloc(sizeof(struct alloc_struct));
		a->offset = offset;
		LIST_INSERT_HEAD(&(a_p_s->allocation_head), a, alloc_ptr);
		a_p_s->last_e = a;
		a_p_s->length = 1;
		print_dsas(8,"%s:D1:alloc_list_size:%lu, a:0x%lx\n",__func__, alloc_list_size, a);
	} else {
		if (list_not_empty(&(a_p_s->allocation_head))) {
			struct alloc_struct* a = malloc(sizeof(struct alloc_struct));
			a->offset = offset;
			LIST_INSERT_AFTER(a_p_s->last_e, a, alloc_ptr);
			a_p_s->last_e = a;
			a_p_s->length++;
			print_dsas(8,"%s:D2:alloc_list_size:%lu, a_p_s->length:%lu, a:0x%lx\n",__func__, alloc_list_size, a_p_s->length, a);
		} else {
			struct alloc_struct* a = malloc(sizeof(struct alloc_struct));
			a->offset = offset;
			LIST_INSERT_HEAD(&(a_p_s->allocation_head), a, alloc_ptr);
			a_p_s->last_e = a;
			a_p_s->length = 1;
			print_dsas(8,"%s:D3:alloc_list_size:%lu, a_p_s->length:%lu, a:0x%lx\n",__func__, alloc_list_size, a_p_s->length, a);
		}
	}

	return 0;
}

int retrieve_from_list(unsigned int size)
{
	struct alloc_list* a_p_s;
	struct alloc_struct *p;
	int random_elem;
	unsigned int offset;

	a_p_s = get_alloc_ptr_of_size(size);

	if (!a_p_s) {
		print_dsas(1,"error: list of this size not found !!!\n");
		return -1;
	}

	if (!list_not_empty(&(a_p_s->allocation_head))) {
		print_dsas(1,"error: No entries found for this size !!!\n");
		return -1;
	}

	random_elem = rand();

	if (random_elem > a_p_s->length)
		random_elem %= a_p_s->length;

	p = get_element_no(&(a_p_s->allocation_head), random_elem);

	if (!p) {
		print_dsas(1,"error: free element retrieved is NULL!!!\n");
		return -1;
	}

	print_dsas(8,"%s:D3:alloc_list_size:%lu, a_p_s->length:%lu, a:0x%lx\n",__func__, alloc_list_size, a_p_s->length, p);

	offset = p->offset;
	LIST_REMOVE(p, alloc_ptr);

	a_p_s->length--;

	if (p == a_p_s->last_e) {
		a_p_s->last_e = get_element_no(&(a_p_s->allocation_head), a_p_s->length - 1);
	}

	free(p);

	return offset;
}

int init_alloc_lists(void)
{
	alloc_list_ptr = (struct alloc_list*) calloc(1, max_num_alloc_sizes * sizeof(struct alloc_list));
	if (!alloc_list_ptr) {
		print_dsas(1,"error: failed to allocate memory for lists\n");
		return -1;
	}

	return 0;
}

struct alloc_list* get_alloc_ptr_of_size(unsigned int size)
{
	unsigned int i;

	for (i = 0; i < alloc_list_size; i++) {
		print_dsas(8,"%s:%lu, 0x%lx, %lu\n", __func__, alloc_list_size, alloc_list_ptr + i, ((struct alloc_list*)(alloc_list_ptr + i))->size);
		if (((struct alloc_list*)(alloc_list_ptr + i))->size == size)
			return (alloc_list_ptr + i);
	}
	
	return NULL;
}

struct alloc_struct *list_not_empty(struct alloc_head* ah)
{
	return ah->lh_first;
}

struct alloc_struct *get_element_no(struct alloc_head* ah, int elem)
{
	int i;
	struct alloc_struct *p;

	for (i = 0, p = ah->lh_first; i < elem; p = p->alloc_ptr.le_next, i++);

	return p;
}

