/*
 *
 *  Copyright (C) 2014 OpenWrt.org
 *  Copyright (C) 2014 Mikko Hissa <mikko.hissa@werzek.com>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 2 as published
 *  by the Free Software Foundation.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
//#include <zlib.h>

#define IH_MAGIC	0x27051956
#define IH_NMLEN	32
#define IH_PRODLEN	23

#define IH_TYPE_INVALID		0
#define IH_TYPE_STANDALONE	1
#define IH_TYPE_KERNEL		2
#define IH_TYPE_RAMDISK		3
#define IH_TYPE_MULTI		4
#define IH_TYPE_FIRMWARE	5
#define IH_TYPE_SCRIPT		6
#define IH_TYPE_FILESYSTEM	7

/*
 * Compression Types
 */
#define IH_COMP_NONE		0
#define IH_COMP_GZIP		1
#define IH_COMP_BZIP2		2
#define IH_COMP_LZMA		3

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

typedef struct {
	uint8_t major;
	uint8_t minor;
} version_t;

typedef struct {
	version_t	kernel;
	version_t	fs;
	uint8_t		productid[IH_PRODLEN];
	uint8_t  	sub_fs;
	uint32_t	ih_ksz;
} asus_t;

typedef struct image_header {
	uint32_t	ih_magic;
	uint32_t	ih_hcrc;
	uint32_t	ih_time;
	uint32_t	ih_size;
	uint32_t	ih_load;
	uint32_t	ih_ep;
	uint32_t	ih_dcrc;
	uint8_t		ih_os;
	uint8_t		ih_arch;
	uint8_t		ih_type;
	uint8_t		ih_comp;
	union {
		uint8_t	ih_name[IH_NMLEN];
		asus_t	asus;
	} tail;
} image_header_t;

typedef struct squashfs_sb {
	uint32_t	s_magic;
	uint32_t	pad0[9];
	uint64_t	bytes_used;
} squashfs_sb_t;

typedef enum {
	NONE, FACTORY, SYSUPGRADE,
} op_mode_t;

void
calc_crc(image_header_t *hdr, void *data, uint32_t len)
{
	/*
	 * Calculate payload checksum
	 */
	hdr->ih_dcrc = htonl(crc32(0, data, len));
	hdr->ih_size = htonl(len);
	/*
	 * Calculate header checksum
	 */
	hdr->ih_hcrc = 0;
	hdr->ih_hcrc = htonl(crc32(0, hdr, sizeof(image_header_t)));
}


static void
usage(const char *progname, int status)
{
	FILE *stream = (status != EXIT_SUCCESS) ? stderr : stdout;
	int i;

	fprintf(stream, "Usage: %s [OPTIONS...]\n", progname);
	fprintf(stream, "\n"
			"Options:\n"
			"  -f <file>		generate a factory flash image <file>\n"
			"  -s <file>		generate a sysupgrade flash image <file>\n"
			"  -h			show this screen\n");
	exit(status);
}

int
process_image(char *progname, char *filename, op_mode_t opmode)
{
	int 		fd, len;
	void 		*data, *ptr;
	char		namebuf[IH_NMLEN];
	struct 		stat sbuf;
	uint32_t	checksum, offset_kernel, offset_sqfs, offset_end,
				offset_sec_header, offset_eb, offset_image_end;
	squashfs_sb_t *sqs;
	image_header_t *hdr;

	if ((fd = open(filename, O_RDWR, 0666)) < 0) {
		fprintf (stderr, "%s: Can't open %s: %s\n",
			progname, filename, strerror(errno));
		return (EXIT_FAILURE);
	}

	if (fstat(fd, &sbuf) < 0) {
		fprintf (stderr, "%s: Can't stat %s: %s\n",
			progname, filename, strerror(errno));
		return (EXIT_FAILURE);
	}

	if ((unsigned)sbuf.st_size < sizeof(image_header_t)) {
		fprintf (stderr,
			"%s: Bad size: \"%s\" is no valid image\n",
			progname, filename);
		return (EXIT_FAILURE);
	}

	ptr = (void *)mmap(0, sbuf.st_size,
				PROT_READ | PROT_WRITE,
				MAP_SHARED,
				fd, 0);

	if ((caddr_t)ptr == (caddr_t)-1) {
		fprintf (stderr, "%s: Can't read %s: %s\n",
			progname, filename, strerror(errno));
		return (EXIT_FAILURE);
	}

	hdr = ptr;

	if (ntohl(hdr->ih_magic) != IH_MAGIC) {
		fprintf (stderr,
			"%s: Bad Magic Number: \"%s\" is no valid image\n",
			progname, filename);
		return (EXIT_FAILURE);
	}

	if (opmode == FACTORY) {
		strncpy(&namebuf, (char *)&hdr->tail.ih_name, IH_NMLEN);
		hdr->tail.asus.kernel.major = 0;
		hdr->tail.asus.kernel.minor = 0;
		hdr->tail.asus.fs.major = 0;
		hdr->tail.asus.fs.minor = 0;
		strncpy((char *)&hdr->tail.asus.productid, "RT-N56U", IH_PRODLEN);
	}

	if (hdr->tail.asus.ih_ksz == 0)
		hdr->tail.asus.ih_ksz = htonl(ntohl(hdr->ih_size) + sizeof(image_header_t));

	offset_kernel = sizeof(image_header_t);
	offset_sqfs = ntohl(hdr->tail.asus.ih_ksz);
	sqs = ptr + offset_sqfs;
	offset_sec_header = offset_sqfs + sqs->bytes_used;

	/*
	 * Reserve space for the second header.
	 */
	offset_end = offset_sec_header + sizeof(image_header_t);
	offset_eb = ((offset_end>>16)+1)<<16;

	if (opmode == FACTORY)
		offset_image_end = offset_eb + 4;
	else
		offset_image_end = sbuf.st_size;
	/*
	 * Move the second header at the end of the image.
	 */
	offset_end = offset_sec_header;
	offset_sec_header = offset_eb - sizeof(image_header_t);

	/*
	 * Remove jffs2 markers between squashfs and eb boundary.
	 */
	if (opmode == FACTORY)
		memset(ptr+offset_end, 0xff ,offset_eb - offset_end);

	/*
	 * Grow the image if needed.
	 */
	if (offset_image_end > sbuf.st_size) {
		(void) munmap((void *)ptr, sbuf.st_size);
		ftruncate(fd, offset_image_end);
		ptr = (void *)mmap(0, offset_image_end,
						PROT_READ | PROT_WRITE,
						MAP_SHARED,
						fd, 0);
		/*
		 * jffs2 marker
		 */
		if (opmode == FACTORY) {
			*(uint8_t *)(ptr+offset_image_end-4) = 0xde;
			*(uint8_t *)(ptr+offset_image_end-3) = 0xad;
			*(uint8_t *)(ptr+offset_image_end-2) = 0xc0;
			*(uint8_t *)(ptr+offset_image_end-1) = 0xde;
		}
	}

	/*
	 * Calculate checksums for the second header to be used after flashing.
	 */
	if (opmode == FACTORY) {
		hdr = ptr+offset_sec_header;
		memcpy(hdr, ptr, sizeof(image_header_t));
		strncpy((char *)&hdr->tail.ih_name, &namebuf, IH_NMLEN);
		calc_crc(hdr, ptr+offset_kernel, offset_sqfs - offset_kernel);
		calc_crc((image_header_t *)ptr, ptr+offset_kernel, offset_image_end - offset_kernel);
	} else {
		calc_crc((image_header_t *)ptr, ptr+offset_kernel, offset_sqfs - offset_kernel);
	}

	if (sbuf.st_size > offset_image_end)
		(void) munmap((void *)ptr, sbuf.st_size);
	else
		(void) munmap((void *)ptr, offset_image_end);

	ftruncate(fd, offset_image_end);
	(void) close (fd);

	return EXIT_SUCCESS;
}

int
main(int argc, char **argv)
{
	int 		opt;
	char 		*filename, *progname;
	op_mode_t	opmode = NONE;

	progname = argv[0];

	while ((opt = getopt(argc, argv,":s:f:h?")) != -1) {
		switch (opt) {
		case 's':
			opmode = SYSUPGRADE;
			filename = optarg;
			break;
		case 'f':
			opmode = FACTORY;
			filename = optarg;
			break;
		case 'h':
			opmode = NONE;
		default:
			usage(progname, EXIT_FAILURE);
			opmode = NONE;
		}
	}

	if(filename == NULL)
		opmode = NONE;

	switch (opmode) {
	case NONE:
		usage(progname, EXIT_FAILURE);
		break;
	case FACTORY:
	case SYSUPGRADE:
		return process_image(progname, filename, opmode);
		break;
	}

	return EXIT_SUCCESS;
}

