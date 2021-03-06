/*
 * Copyright (C) 2007 Ubiquiti Networks, Inc.
 * Copyright (C) 2008 Lukas Kuna <ValXdater@seznam.cz>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
//#include <zlib.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "fw.h"

typedef struct fw_layout_data {
	char		name[PATH_MAX];
	u_int32_t	kern_start;
	u_int32_t	kern_entry;
	u_int32_t	firmware_max_length;
} fw_layout_t;

fw_layout_t fw_layout_data[] = {
	{
		.name		=	"XS2",
		.kern_start	=	0xbfc30000,
		.kern_entry	=	0x80041000,
		.firmware_max_length=	0x00390000,
	},
	{
		.name		=	"XS5",
		.kern_start	=	0xbe030000,
		.kern_entry	=	0x80041000,
		.firmware_max_length=	0x00390000,
	},
	{
		.name		=	"RS",
		.kern_start	=	0xbf030000,
		.kern_entry	=	0x80060000,
		.firmware_max_length=	0x00B00000,
	},
	{
		.name		=	"RSPRO",
		.kern_start	=	0xbf030000,
		.kern_entry	=	0x80060000,
		.firmware_max_length=	0x00F00000,
	},
	{
		.name		=	"LS-SR71",
		.kern_start	=	0xbf030000,
		.kern_entry	=	0x80060000,
		.firmware_max_length=	0x00640000,
	},
	{
		.name		=	"XS2-8",
		.kern_start	=	0xa8030000,
		.kern_entry	=	0x80041000,
		.firmware_max_length=	0x006C0000,
	},
	{
		.name		=	"XM",
		.kern_start	=	0x9f050000,
		.kern_entry	=	0x80002000,
		.firmware_max_length=	0x006A0000,
	},
	{	.name		=	"",
	},
};

typedef struct part_data {
	char 	partition_name[64];
	int  	partition_index;
	u_int32_t	partition_baseaddr;
	u_int32_t	partition_startaddr;
	u_int32_t	partition_memaddr;
	u_int32_t	partition_entryaddr;
	u_int32_t  partition_length;

	char	filename[PATH_MAX];
	struct stat stats;
} part_data_t;

#define MAX_SECTIONS	8
#define DEFAULT_OUTPUT_FILE 	"firmware-image.bin"
#define DEFAULT_VERSION		"UNKNOWN"

#define OPTIONS "B:hv:m:o:r:k:"

static int debug = 0;

typedef struct image_info {
	char magic[16];
	char version[256];
	char outputfile[PATH_MAX];
	u_int32_t	part_count;
	part_data_t parts[MAX_SECTIONS];
} image_info_t;

static uint32_t crc32tab[256] = {
	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
	0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
	0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
	0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
	0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
	0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
	0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
	0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
	0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
	0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
	0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
	0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
	0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
	0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
	0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
	0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
	0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
	0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
	0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
	0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
	0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
	0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
	0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
	0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
	0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
	0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
	0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
	0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
	0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
	0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
	0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

uint32_t crc32(uint32_t crc, uint8_t *data, size_t len)
{
	while (len--)
		crc = (crc >> 8) ^ crc32tab[(crc ^ *data++) & 0xFF];

	return crc;
}

static void write_header(void* mem, const char *magic, const char* version)
{
	header_t* header = mem;
	memset(header, 0, sizeof(header_t));

	memcpy(header->magic, magic, MAGIC_LENGTH);
	strncpy(header->version, version, sizeof(header->version));
	header->crc = htonl(crc32(0L, (unsigned char *)header,
				sizeof(header_t) - 2 * sizeof(u_int32_t)));
	header->pad = 0L;
}


static void write_signature(void* mem, u_int32_t sig_offset)
{
	/* write signature */
	signature_t* sign = (signature_t*)(mem + sig_offset);
	memset(sign, 0, sizeof(signature_t));

	memcpy(sign->magic, MAGIC_END, MAGIC_LENGTH);
	sign->crc = htonl(crc32(0L,(unsigned char *)mem, sig_offset));
	sign->pad = 0L;
}

static int write_part(void* mem, part_data_t* d)
{
	char* addr;
	int fd;
	part_t* p = mem;
	part_crc_t* crc = mem + sizeof(part_t) + d->stats.st_size;

	fd = open(d->filename, O_RDONLY);
	if (fd < 0)
	{
		ERROR("Failed opening file '%s'\n", d->filename);
		return -1;
	}

	if ((addr=(char*)mmap(0, d->stats.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
	{
		ERROR("Failed mmaping memory for file '%s'\n", d->filename);
		close(fd);
		return -2;
	}

	memcpy(mem + sizeof(part_t), addr, d->stats.st_size);
	munmap(addr, d->stats.st_size);

	memset(p->name, 0, sizeof(p->name));
	strncpy(p->magic, MAGIC_PART, MAGIC_LENGTH);
	strncpy(p->name, d->partition_name, sizeof(p->name));
	p->index = htonl(d->partition_index);
	p->data_size = htonl(d->stats.st_size);
	p->part_size = htonl(d->partition_length);
	p->baseaddr = htonl(d->partition_baseaddr);
	p->memaddr = htonl(d->partition_memaddr);
	p->entryaddr = htonl(d->partition_entryaddr);

	crc->crc = htonl(crc32(0L, mem, d->stats.st_size + sizeof(part_t)));
	crc->pad = 0L;

	return 0;
}

static void usage(const char* progname)
{
	INFO("Version %s\n"
             "Usage: %s [options]\n"
	     "\t-v <version string>\t - firmware version information, default: %s\n"
	     "\t-o <output file>\t - firmware output file, default: %s\n"
	     "\t-m <magic>\t - firmware magic, default: %s\n"
	     "\t-k <kernel file>\t\t - kernel file\n"
	     "\t-r <rootfs file>\t\t - rootfs file\n"
	     "\t-B <board name>\t\t - choose firmware layout for specified board (XS2, XS5, RS, XM)\n"
	     "\t-h\t\t\t - this help\n", VERSION,
	     progname, DEFAULT_VERSION, DEFAULT_OUTPUT_FILE, MAGIC_HEADER);
}

static void print_image_info(const image_info_t* im)
{
	int i = 0;
	INFO("Firmware version: '%s'\n"
	     "Output file: '%s'\n"
	     "Part count: %u\n",
	     im->version, im->outputfile,
	     im->part_count);

	for (i = 0; i < im->part_count; ++i)
	{
		const part_data_t* d = &im->parts[i];
		INFO(" %10s: %8ld bytes (free: %8ld)\n",
		     d->partition_name,
		     d->stats.st_size,
		     d->partition_length - d->stats.st_size);
	}
}



static u_int32_t filelength(const char* file)
{
	FILE *p;
	int ret = -1;

	if ( (p = fopen(file, "rb") ) == NULL) return (-1);

	fseek(p, 0, SEEK_END);
	ret = ftell(p);

	fclose (p);

	return (ret);
}

static int create_image_layout(const char* kernelfile, const char* rootfsfile, char* board_name, image_info_t* im)
{
	part_data_t* kernel = &im->parts[0];
	part_data_t* rootfs = &im->parts[1];

	fw_layout_t* p;

	p = &fw_layout_data[0];
	while ((strlen(p->name) != 0) && (strncmp(p->name, board_name, sizeof(board_name)) != 0))
		p++;
	if (p->name == NULL) {
		printf("BUG! Unable to find default fw layout!\n");
		exit(-1);
	}

	printf("board = %s\n", p->name);
	strcpy(kernel->partition_name, "kernel");
	kernel->partition_index = 1;
	kernel->partition_baseaddr = p->kern_start;
	if ( (kernel->partition_length = filelength(kernelfile)) < 0) return (-1);
	kernel->partition_memaddr = p->kern_entry;
	kernel->partition_entryaddr = p->kern_entry;
	strncpy(kernel->filename, kernelfile, sizeof(kernel->filename));

	if (filelength(rootfsfile) + kernel->partition_length > p->firmware_max_length)
		return (-2);

	strcpy(rootfs->partition_name, "rootfs");
	rootfs->partition_index = 2;
	rootfs->partition_baseaddr = kernel->partition_baseaddr + kernel->partition_length;
	rootfs->partition_length = p->firmware_max_length - kernel->partition_length;
	rootfs->partition_memaddr = 0x00000000;
	rootfs->partition_entryaddr = 0x00000000;
	strncpy(rootfs->filename, rootfsfile, sizeof(rootfs->filename));

printf("kernel: %d 0x%08x\n", kernel->partition_length, kernel->partition_baseaddr);
printf("root: %d 0x%08x\n", rootfs->partition_length, rootfs->partition_baseaddr);
	im->part_count = 2;

	return 0;
}

/**
 * Checks the availability and validity of all image components.
 * Fills in stats member of the part_data structure.
 */
static int validate_image_layout(image_info_t* im)
{
	int i;

	if (im->part_count == 0 || im->part_count > MAX_SECTIONS)
	{
		ERROR("Invalid part count '%d'\n", im->part_count);
		return -1;
	}

	for (i = 0; i < im->part_count; ++i)
	{
		part_data_t* d = &im->parts[i];
		int len = strlen(d->partition_name);
		if (len == 0 || len > 16)
		{
			ERROR("Invalid partition name '%s' of the part %d\n",
					d->partition_name, i);
			return -1;
		}
		if (stat(d->filename, &d->stats) < 0)
		{
			ERROR("Couldn't stat file '%s' from part '%s'\n",
				       	d->filename, d->partition_name);
			return -2;
		}
		if (d->stats.st_size == 0)
		{
			ERROR("File '%s' from part '%s' is empty!\n",
				       	d->filename, d->partition_name);
			return -3;
		}
		if (d->stats.st_size > d->partition_length) {
			ERROR("File '%s' too big (%d) - max size: 0x%08X (exceeds %lu bytes)\n",
				       	d->filename, i, d->partition_length,
					d->stats.st_size - d->partition_length);
			return -4;
		}
	}

	return 0;
}

static int build_image(image_info_t* im)
{
	char* mem;
	char* ptr;
	u_int32_t mem_size;
	FILE* f;
	int i;

	// build in-memory buffer
	mem_size = sizeof(header_t) + sizeof(signature_t);
	for (i = 0; i < im->part_count; ++i)
	{
		part_data_t* d = &im->parts[i];
		mem_size += sizeof(part_t) + d->stats.st_size + sizeof(part_crc_t);
	}

	mem = (char*)calloc(mem_size, 1);
	if (mem == NULL)
	{
		ERROR("Cannot allocate memory chunk of size '%u'\n", mem_size);
		return -1;
	}

	// write header
	write_header(mem, im->magic, im->version);
	ptr = mem + sizeof(header_t);
	// write all parts
	for (i = 0; i < im->part_count; ++i)
	{
		part_data_t* d = &im->parts[i];
		int rc;
		if ((rc = write_part(ptr, d)) != 0)
		{
			ERROR("ERROR: failed writing part %u '%s'\n", i, d->partition_name);
		}
		ptr += sizeof(part_t) + d->stats.st_size + sizeof(part_crc_t);
	}
	// write signature
	write_signature(mem, mem_size - sizeof(signature_t));

	// write in-memory buffer into file
	if ((f = fopen(im->outputfile, "w")) == NULL)
	{
		ERROR("Can not create output file: '%s'\n", im->outputfile);
		return -10;
	}

	if (fwrite(mem, mem_size, 1, f) != 1)
	{
		ERROR("Could not write %d bytes into file: '%s'\n",
				mem_size, im->outputfile);
		return -11;
	}

	free(mem);
	fclose(f);
	return 0;
}


int main(int argc, char* argv[])
{
	char kernelfile[PATH_MAX];
	char rootfsfile[PATH_MAX];
	char board_name[PATH_MAX];
	int o, rc;
	image_info_t im;

	memset(&im, 0, sizeof(im));
	memset(kernelfile, 0, sizeof(kernelfile));
	memset(rootfsfile, 0, sizeof(rootfsfile));
	memset(board_name, 0, sizeof(board_name));

	strcpy(im.outputfile, DEFAULT_OUTPUT_FILE);
	strcpy(im.version, DEFAULT_VERSION);
	strncpy(im.magic, MAGIC_HEADER, sizeof(im.magic));

	while ((o = getopt(argc, argv, OPTIONS)) != -1)
	{
		switch (o) {
		case 'v':
			if (optarg)
				strncpy(im.version, optarg, sizeof(im.version));
			break;
		case 'o':
			if (optarg)
				strncpy(im.outputfile, optarg, sizeof(im.outputfile));
			break;
		case 'm':
			if (optarg)
				strncpy(im.magic, optarg, sizeof(im.magic));
			break;
		case 'h':
			usage(argv[0]);
			return -1;
		case 'k':
			if (optarg)
				strncpy(kernelfile, optarg, sizeof(kernelfile));
			break;
		case 'r':
			if (optarg)
				strncpy(rootfsfile, optarg, sizeof(rootfsfile));
			break;
		case 'B':
			if (optarg)
				strncpy(board_name, optarg, sizeof(board_name));
			break;
		}
	}
	if (strlen(board_name) == 0)
		strcpy(board_name, "XS2"); /* default to XS2 */

	if (strlen(kernelfile) == 0)
	{
		ERROR("Kernel file is not specified, cannot continue\n");
		usage(argv[0]);
		return -2;
	}

	if (strlen(rootfsfile) == 0)
	{
		ERROR("Root FS file is not specified, cannot continue\n");
		usage(argv[0]);
		return -2;
	}

	if ((rc = create_image_layout(kernelfile, rootfsfile, board_name, &im)) != 0)
	{
		ERROR("Failed creating firmware layout description - error code: %d\n", rc);
		return -3;
	}

	if ((rc = validate_image_layout(&im)) != 0)
	{
		ERROR("Failed validating firmware layout - error code: %d\n", rc);
		return -4;
	}

	print_image_info(&im);

	if ((rc = build_image(&im)) != 0)
	{
		ERROR("Failed building image file '%s' - error code: %d\n", im.outputfile, rc);
		return -5;
	}

	return 0;
}
