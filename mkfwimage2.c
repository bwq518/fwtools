/*
 * Copyright (C) 2007 Ubiquiti Networks, Inc.
 * Copyright (C) 2008 Lukas Kuna <ValXdater@seznam.cz>
 * Copyright (C) 2008 Gabor Juhos <juhosg@openwrt.org>
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

#undef VERSION
#define VERSION "1.2-OpenWrt.1"

#define MAX_SECTIONS		8
#define DEFAULT_OUTPUT_FILE 	"firmware-image.bin"
#define DEFAULT_VERSION		"UNKNOWN"
#define DEFAULT_FLASH_BASE	(0xbfc00000)

#define FIRMWARE_MAX_LENGTH	(0x390000)

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

typedef struct part_data {
	char 		partition_name[64];
	int  		partition_index;
	u_int32_t	partition_baseaddr;
	u_int32_t	partition_offset;
	u_int32_t	partition_memaddr;
	u_int32_t	partition_entryaddr;
	u_int32_t	partition_length;

	char		filename[PATH_MAX];
	struct stat	stats;
} part_data_t;

typedef struct image_info {
	char		version[256];
	char		outputfile[PATH_MAX];
	char		magic[MAGIC_LENGTH];
	u_int32_t	flash_baseaddr;
	u_int32_t	part_count;
	part_data_t	parts[MAX_SECTIONS];
} image_info_t;

static image_info_t im;
static int debug = 0;
static int zero_part_baseaddr = 0;

static void write_header(void* mem, const char* version)
{
	header_t* header = mem;
	memset(header, 0, sizeof(header_t));

	memcpy(header->magic, im.magic, MAGIC_LENGTH);
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
	if (fd < 0) {
		ERROR("Failed opening file '%s'\n", d->filename);
		return -1;
	}

	if ((addr=(char*)mmap(0, d->stats.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
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
	     "\t-m <magic>\t\t - firmware magic, default: %s\n"
	     "\t-f <flash base>\t\t - flash base address, default: 0x%08x\n"
	     "\t-o <output file>\t - firmware output file, default: %s\n"
	     "\t-p <name>:<offset>:<len>:<memaddr>:<entry>:<file>\n "
	     "\t\t\t\t - create a partition from <file>\n"
	     "\t-z\t\t\t - set partition offsets to zero\n"
	     "\t-h\t\t\t - this help\n",
	     VERSION, progname, DEFAULT_VERSION, MAGIC_HEADER,
	     DEFAULT_FLASH_BASE, DEFAULT_OUTPUT_FILE);
}

static void print_image_info(void)
{
	int i;

	INFO("Firmware version : '%s'\n"
	     "Output file      : '%s'\n"
	     "Part count       : %u\n",
	     im.version, im.outputfile, im.part_count);

	for (i = 0; i < im.part_count; ++i) {
		const part_data_t* d = &im.parts[i];
		INFO("  %10s: %08x %08x %08x %08x %8ld bytes (free: %8ld)\n",
		     d->partition_name,
		     d->partition_baseaddr,
		     d->partition_length,
		     d->partition_entryaddr,
		     d->partition_memaddr,
		     d->stats.st_size,
		     d->partition_length - d->stats.st_size);
	}
}

static int filelength(const char* file)
{
	FILE *p;
	int ret = -1;

	if ( (p = fopen(file, "rb") ) == NULL) return (-1);

	fseek(p, 0, SEEK_END);
	ret = ftell(p);

	fclose (p);

	return (ret);
}

int str2u32(char *arg, u_int32_t *val)
{
	char *err = NULL;
	uint32_t t;

	errno = 0;
	t = strtoul(arg, &err, 0);
	if (errno || (err == arg) || ((err != NULL) && *err)) {
		return -1;
	}

	*val = t;
	return 0;
}

static int image_layout_add_partition(const char *part_desc)
{
	part_data_t *d;
	char memaddr[16];
	char entryaddr[16];
	char offset[16];
	char length[16];
	int t;

	if (im.part_count >= MAX_SECTIONS) {
		ERROR("Too many partitions specified\n");
		return (-1);
	}

	d = &im.parts[im.part_count];
	t = sscanf(part_desc, "%15[0-9a-zA-Z]:%15[0-9a-fA-Fx]:%15[0-9a-fA-Fx]:%15[0-9a-fA-Fx]:%15[0-9a-fA-Fx]:%256s",
			d->partition_name,
			offset,
			length,
			memaddr,
			entryaddr,
			d->filename);

	if (t != 6) {
		ERROR("Bad partition parameter %d, '%s'\n", t, part_desc);
		return (-1);
	}

	if (strlen(d->partition_name) == 0) {
		ERROR("No partition name specified in '%s'\n", part_desc);
		return (-1);
	}

	if (str2u32(offset, &d->partition_offset)) {
		ERROR("Bad offset value '%s'\n", offset);
		return (-1);
	}

	if (str2u32(length, &d->partition_length)) {
		ERROR("Bad length value '%s'\n", length);
		return (-1);
	}

	if (d->partition_length == 0) {
		int flen;
		flen = filelength(d->filename);
		if (flen < 0) {
			ERROR("Unable to determine size of '%s'\n",
					d->filename);
			return (-1);
		}
		d->partition_length = flen;
	}

	if (str2u32(memaddr, &d->partition_memaddr)) {
		ERROR("Bad memaddr vaule '%s'\n", memaddr);
		return (-1);
	}

	if (str2u32(entryaddr, &d->partition_entryaddr)) {
		ERROR("Bad entry address value '%s'\n", entryaddr);
		return (-1);
	}

	im.part_count++;
	d->partition_index = im.part_count;

	return 0;
}

static int image_layout_verify(void)
{
	u_int32_t offset;
	int i;

	if (im.part_count == 0) {
		ERROR("No partitions specified\n");
		return -1;
	}

	offset = im.parts[0].partition_offset;
	for (i = 0; i < im.part_count; i++)
	{
		part_data_t* d = &im.parts[i];

		if (stat(d->filename, &d->stats) < 0) {
			ERROR("Couldn't stat file '%s' from part '%s'\n",
					d->filename, d->partition_name);
			return -2;
		}

		if (d->stats.st_size == 0) {
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

		if (d->partition_offset < offset)
			d->partition_offset = offset;

		if (zero_part_baseaddr) {
			d->partition_baseaddr = 0;
		} else {
			d->partition_baseaddr =
				im.flash_baseaddr + d->partition_offset;
		}
		offset += d->partition_length;
	}

	return 0;
}

static int build_image(void)
{
	char* mem;
	char* ptr;
	u_int32_t mem_size;
	FILE* f;
	int i;

	/* build in-memory buffer */
	mem_size = sizeof(header_t) + sizeof(signature_t);
	for (i = 0; i < im.part_count; ++i) {
		part_data_t* d = &im.parts[i];
		mem_size += sizeof(part_t) + d->stats.st_size + sizeof(part_crc_t);
	}

	mem = (char*)calloc(mem_size, 1);
	if (mem == NULL) {
		ERROR("Cannot allocate memory chunk of size '%u'\n", mem_size);
		return -1;
	}

	/* write header */
	write_header(mem, im.version);
	ptr = mem + sizeof(header_t);

	/* write all parts */
	for (i = 0; i < im.part_count; ++i) {
		part_data_t* d = &im.parts[i];
		int rc;
		if ((rc = write_part(ptr, d)) != 0) {
			ERROR("ERROR: failed writing part %u '%s'\n", i, d->partition_name);
			return -1;
		}
		ptr += sizeof(part_t) + d->stats.st_size + sizeof(part_crc_t);
	}


	/* write signature */
	write_signature(mem, mem_size - sizeof(signature_t));

	/* write in-memory buffer into file */
	if ((f = fopen(im.outputfile, "w")) == NULL) {
		ERROR("Can not create output file: '%s'\n", im.outputfile);
		return -10;
	}

	if (fwrite(mem, mem_size, 1, f) != 1) {
		ERROR("Could not write %d bytes into file: '%s'\n",
				mem_size, im.outputfile);
		return -11;
	}

	free(mem);
	fclose(f);
	return 0;
}

int main(int argc, char* argv[])
{
	int o, rc;

	memset(&im, 0, sizeof(im));

	strcpy(im.outputfile, DEFAULT_OUTPUT_FILE);
	strcpy(im.version, DEFAULT_VERSION);
	memcpy(im.magic, MAGIC_HEADER, MAGIC_LENGTH);
	im.flash_baseaddr = DEFAULT_FLASH_BASE;

	while ((o = getopt(argc, argv, "f:hm:o:p:v:z")) != -1)
	{
		switch (o) {
		case 'f':
			if (optarg)
				if (str2u32(optarg, &im.flash_baseaddr)) {
					ERROR("Invalid flash start address %s\n", optarg);
					return -1;
				}
			break;
		case 'h':
			usage(argv[0]);
			return -1;
		case 'm':
			if (optarg) {
				if (strlen(optarg) != MAGIC_LENGTH) {
					ERROR("Invalid magic %s\n", optarg);
					return -1;
				}

				memcpy(im.magic, optarg, MAGIC_LENGTH);
			}
			break;
		case 'o':
			if (optarg)
				strncpy(im.outputfile, optarg, sizeof(im.outputfile));
			break;
		case 'p':
			if (optarg) {
				if (image_layout_add_partition(optarg))
					return -1;
			}
			break;
		case 'v':
			if (optarg)
				strncpy(im.version, optarg, sizeof(im.version));
			break;
		case 'z':
			zero_part_baseaddr = 1;
			break;
		}
	}

	rc = image_layout_verify();
	if (rc)	{
		ERROR("Failed validating firmware layout - error code: %d\n",
				rc);
		return -4;
	}

	print_image_info();

	rc = build_image();
	if (rc)	{
		ERROR("Failed building image file '%s' - error code: %d\n",
				im.outputfile, rc);
		return -5;
	}

	return 0;
}
