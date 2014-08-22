#
# Copyright (C.o 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

EXE= 	addpattern trx motorola-bin dgfirmware trx2usr ptgen airlink srec2bin \
	mkmylofw mkcsysimg mkzynfw mkcasfw add_header makeamitbin encode_crc nand_ecc pc1crypt \
	osbridge-crc mkdniimg mktitanimg mkchkimg spw303v zyxbcm trx2edips xorimage mkedimaximg mkbrncmdline \
	mkbrnimg mkdapimg mkcameofw mkporayfw mkdcs932 dgn3500sum


OBJS= 	addpattern.o trx.o motorola-bin.o dgfirmware.o mksenaofw.o md5.o trx2usr.o ptgen.o airlink.o srec2bin.o \
	mkmylofw.o mkcsysimg.o mkzynfw.o lzma2eva.o mkcasfw.o mkfwimage.o mkfwimage2.o imagetag.o imagetag_cmdline.o \
	add_header.o makeamitbin.o encode_crc.o nand_ecc.o mkplanexfw.o sha1.o mktplinkfw.o mktplinkfw2.o pc1crypt.o \
	osbridge-crc.o wrt400n.o cyg_crc32.o mkdniimg.o mktitanimg.o mkchkimg.o mkzcfw.o spw303v.o zyxbcm.o trx2edips.o \
	xorimage.o buffalo-enc.o buffalo-lib.o buffalo-tag.o buffalo-tftp.o mkwrgimg.o mkedimaximg.o mkbrncmdline.o \
	mkbrnimg.o mkdapimg.o mkcameofw.o seama.o fix-u-media-header.o hcsmakeimage.o bcmalgo.o mkporayfw.o mkhilinkfw.o \
	mkdcs932.o mkheader_gemtek.o mkrtn56uimg.o dgn3500sum.o

EXE_E=	hcsmakeimage \
	mksenaofw \
	lzma2eva \
	mkfwimage \
	mkfwimage2 \
	mkplanexfw \
	imagetag \
	mktplinkfw \
	mktplinkfw2 \
	wrt400n \
	mkzcfw \
	buffalo-enc \
	buffalo-tag \
	buffalo-tftp \
	mkwrgimg \
	seama \
	fix-u-media-header \
	mkheader_gemtek \
	mkrtn56uimg
#	mkhilinkfw \

all: 	$(OBJS) $(EXE) $(EXE_E)

mkrtn56uimg: mkrtn56uimg.o cyg_crc32.o
	cc -static -lz -lcrypto mkrtn56uimg.o cyg_crc32.o -o mkrtn56uimg

mkheader_gemtek: mkheader_gemtek.o cyg_crc32.o
	cc -static -lz -lcrypto mkheader_gemtek.o cyg_crc32.o -o mkheader_gemtek

mkhilinkfw: mkhilinkfw.o sha1.o md5.o
	cc -static -lz -lcrypto -lssl mkhilinkfw.o sha1.o md5.o -o mkhilinkfw

seama: seama.o md5.o
	cc -static -lz -lcrypto seama.o md5.o -o seama

fix-u-media-header: fix-u-media-header.o cyg_crc32.o
	cc -static -lz -lcrypto fix-u-media-header.o cyg_crc32.o -o fix-u-media-header

mkwrgimg: mkwrgimg.o md5.o
	cc -static -lz -lcrypto mkwrgimg.o md5.o -o mkwrgimg

buffalo-enc: buffalo-enc.o buffalo-lib.o
	cc -static -lz -lcrypto buffalo-enc.o buffalo-lib.o -o buffalo-enc

buffalo-tag: buffalo-tag.o buffalo-lib.o
	cc -static -lz -lcrypto buffalo-tag.o buffalo-lib.o -o buffalo-tag

buffalo-tftp: buffalo-tftp.o buffalo-lib.o
	cc -static -lz -lcrypto buffalo-tftp.o buffalo-lib.o -o buffalo-tftp

hcsmakeimage: hcsmakeimage.o bcmalgo.o
	cc -static -lz -lcrypto hcsmakeimage.o bcmalgo.o -o hcsmakeimage

mksenaofw: mksenaofw.o md5.o
	cc -static -lz -lcrypto mksenaofw.o md5.o -o mksenaofw

lzma2eva: lzma2eva.o cyg_crc32.o
	cc -static -lz -lcrypto lzma2eva.o cyg_crc32.o -o lzma2eva

mkfwimage: mkfwimage.o cyg_crc32.o
	cc -static -lz -lcrypto mkfwimage.o cyg_crc32.o -o mkfwimage

mkfwimage2: mkfwimage2.o cyg_crc32.o
	cc -static -lz -lcrypto mkfwimage2.o cyg_crc32.o -o mkfwimage2

imagetag: imagetag.o imagetag_cmdline.o
	cc -static -lz -lcrypto imagetag.o imagetag_cmdline.o -o imagetag

mkplanexfw: mkplanexfw.o sha1.o
	cc -static -lz -lcrypto mkplanexfw.o sha1.o -o mkplanexfw

mktplinkfw: mktplinkfw.o md5.o
	cc -static -lz -lcrypto mktplinkfw.o md5.o -o mktplinkfw

mktplinkfw2: mktplinkfw2.o md5.o
	cc -static -lz -lcrypto mktplinkfw2.o md5.o -o mktplinkfw2

wrt400n: wrt400n.o cyg_crc32.o
	cc -static -lz -lcrypto wrt400n.o cyg_crc32.o -o wrt400n

mkzcfw: mkzcfw.o cyg_crc32.o
	cc -static -lz -lcrypto mkzcfw.o cyg_crc32.o -o mkzcfw

$(EXE): %: %.o
	cc -static -lz -lcrypto $< -o $@

$(OBJS): %.o: %.c
	cc -w -c $< -o $@
	
clean:
	rm -f *.o $(EXE) $(EXE_E) $(OBJS)

