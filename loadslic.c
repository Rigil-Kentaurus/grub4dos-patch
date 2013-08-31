typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
#ifdef __x86_64__
typedef unsigned long u64;
#else
typedef unsigned long long u64;
#endif
#define ACPI_OEM_ID_SIZE        6
#define ACPI_OEM_TABLE_ID_SIZE  8
#define ACPI_NAME_SIZE          4
#define SLIC_LENGTH             0x176

/*******************************************************************************
 *
 * Fundamental ACPI tables
 *
 * This file contains definitions for the ACPI tables that are directly consumed
 * by ACPICA. All other tables are consumed by the OS-dependent ACPI-related
 * device drivers and other OS support code.
 *
 * The RSDP and FACS do not use the common ACPI table header. All other ACPI
 * tables use the header.
 *
 ******************************************************************************/

/*
 * Values for description table header signatures for tables defined in this
 * file. Useful because they make it more difficult to inadvertently type in
 * the wrong signature.
 */
#define ACPI_SIG_DSDT           "DSDT"	/* Differentiated System Description Table */
#define ACPI_SIG_FADT           "FACP"	/* Fixed ACPI Description Table */
#define ACPI_SIG_FACS           "FACS"	/* Firmware ACPI Control Structure */
#define ACPI_SIG_PSDT           "PSDT"	/* Persistent System Description Table */
#define ACPI_SIG_RSDP           "RSD PTR "	/* Root System Description Pointer */
#define ACPI_SIG_RSDT           "RSDT"	/* Root System Description Table */
#define ACPI_SIG_XSDT           "XSDT"	/* Extended  System Description Table */
#define ACPI_SIG_SSDT           "SSDT"	/* Secondary System Description Table */
#define ACPI_RSDP_NAME          "RSDP"	/* Short name for RSDP, not signature */

/*
 * All tables and structures must be byte-packed to match the ACPI
 * specification, since the tables are provided by the system BIOS
 */
#pragma pack(1)

/*******************************************************************************
 *
 * RSDP - Root System Description Pointer (Signature is "RSD PTR ")
 *        Version 2
 *
 ******************************************************************************/

struct acpi_table_rsdp {
	char signature[8];	/* ACPI signature, contains "RSD PTR " */
	u8 checksum;		/* ACPI 1.0 checksum */
	char oem_id[ACPI_OEM_ID_SIZE];	/* OEM identification */
	u8 revision;		/* Must be (0) for ACPI 1.0 or (2) for ACPI 2.0+ */
	u32 rsdt_physical_address;	/* 32-bit physical address of the RSDT */
	u32 length;		/* Table length in bytes, including header (ACPI 2.0+) */
	u64 xsdt_physical_address;	/* 64-bit physical address of the XSDT (ACPI 2.0+) */
	u8 extended_checksum;	/* Checksum of entire table (ACPI 2.0+) */
	u8 reserved[3];		/* Reserved, must be zero */
};

/*******************************************************************************
 *
 * Master ACPI Table Header. This common header is used by all ACPI tables
 * except the RSDP and FACS.
 *
 ******************************************************************************/

struct acpi_table_header {
	char signature[ACPI_NAME_SIZE];	/* ASCII table signature */
	u32 length;		/* Length of table in bytes, including this header */
	u8 revision;		/* ACPI Specification minor version number */
	u8 checksum;		/* To make sum of entire table == 0 */
	char oem_id[ACPI_OEM_ID_SIZE];	/* ASCII OEM identification */
	char oem_table_id[ACPI_OEM_TABLE_ID_SIZE];	/* ASCII OEM table identification */
	u32 oem_revision;	/* OEM revision number */
	char asl_compiler_id[ACPI_NAME_SIZE];	/* ASCII ASL compiler vendor ID */
	u32 asl_compiler_revision;	/* ASL compiler version */
};

/*******************************************************************************
 *
 * RSDT/XSDT - Root System Description Tables
 *             Version 1 (both)
 *
 ******************************************************************************/

struct acpi_table_rsdt {
	struct acpi_table_header header;	/* Common ACPI table header */
	u32 table_offset_entry[1];	/* Array of pointers to ACPI tables */
};

struct acpi_table_xsdt {
	struct acpi_table_header header;	/* Common ACPI table header */
	u64 table_offset_entry[1];	/* Array of pointers to ACPI tables */
};

/* Reset to default packing */

#pragma pack()

static inline u8 checksum(u8 * b, u32 length)
{
	u8 sum = 0, *i = b;
	b += length;
	for (; i < b; sum += *(i++)) ;
	return sum;
}

#define ACPI_RSDP_SCAN_STEP             16
#define ACPI_RSDP_CHECKSUM_LENGTH       20
#define ACPI_RSDP_XCHECKSUM_LENGTH      36
static struct acpi_table_rsdp *acpi_scan_for_rsdp(u8 * begin, u32 length)
{
	struct acpi_table_rsdp *rsdp;
	u8 *i, *end = begin + length;
	for (i = begin; i < end; i += ACPI_RSDP_SCAN_STEP) {
		if (memcmp((char *)i, ACPI_SIG_RSDP, sizeof(ACPI_SIG_RSDP) - 1) != 0)
			continue;
		rsdp = (struct acpi_table_rsdp *)i;
		if (checksum((u8 *) rsdp, ACPI_RSDP_CHECKSUM_LENGTH) != 0)
			continue;
		if (rsdp->revision < 2)
			continue;
		if (checksum((u8 *) rsdp, ACPI_RSDP_XCHECKSUM_LENGTH) != 0)
			continue;
		return rsdp;
	}
	return NULL;
}

static u32 acpi_get_ebda(void)
{
	u32 ebda;
	u16 *base = (u16 *) RAW_ADDR(0x40e);
	if (base != NULL) {
		ebda = *base;
		ebda <<= 4;
	} else {
		ebda = 0xa0000 - 0x400;
	}
	return ebda;
}

#define PADDING(x, y) (((u32)x + y - 1) & (~(y - 1)))

static u8 *acpi_scan_for_freemem(u8 * begin, u32 length, u32 size)
{
	u8 *i, *end = begin + length;
	size = PADDING(size, ACPI_RSDP_SCAN_STEP);
	for (i = begin; i < end; i += ACPI_RSDP_SCAN_STEP) {
		int k = -1;
		volatile u8 *j;
		for (j = i; j < i + size; ++j) {
			if (*j != 0x0) {
				k = 0;
				break;
			}
		}
		if (k == 0) {
			continue;
		}
		for (j = i; j < i + size; ++j) {
			*j = 0xff;
			if (*j != 0xff) {
				k = 0;
				break;
			}
			*j = 0x0;
		}
		if (k == 0) {
			continue;
		}
		return i;
	}
	return NULL;
}

static u8 *acpi_get_mem_rsdp(u32 size)
{
	u32 ebda = acpi_get_ebda();
	u8 *mem = acpi_scan_for_freemem((u8 *) RAW_ADDR(ebda), 0x400, size);
	if (mem == NULL) {
		mem = acpi_scan_for_freemem((u8 *) RAW_ADDR(0xe0000), 0x20000, size);
	}
	return mem;
}

static u8 *acpi_get_mem(u32 size)
{
	u32 ebda = acpi_get_ebda();
	u8 *mem = acpi_scan_for_freemem((u8 *) RAW_ADDR(0x90000), ebda - 0x90000, size);
	if (mem == NULL) {
		mem = acpi_get_mem_rsdp(size);
	}
	/* mark as alloced */
	while (size > 0) {
		--size;
		*(mem + size) = 0xac;
	}
	return mem;
}

static struct acpi_table_rsdp *acpi_find_rsdp(void)
{
	struct acpi_table_rsdp *rsdp = NULL;
	rsdp = acpi_scan_for_rsdp((u8 *) RAW_ADDR(acpi_get_ebda()), 0x400);
	if (rsdp) {
		if (debug < 0) {
			grub_printf("found rsdp in ebda\n");
		}
	} else {
		rsdp = acpi_scan_for_rsdp((u8 *) RAW_ADDR(0xe0000), 0x20000);
		if (rsdp) {
			if (debug < 0) {
				grub_printf("found rsdp in bios\n");
			}
		}
	}
	return rsdp;
}

static struct acpi_table_header *acpi_find_slic(struct acpi_table_rsdt *rsdt)
{
	int i, rsdt_entries;
	struct acpi_table_header *slic;
	rsdt_entries = (rsdt->header.length - sizeof(struct acpi_table_header)) / sizeof(u32);
	for (i = 0; i < rsdt_entries; ++i) {
		slic = (struct acpi_table_header *)(RAW_ADDR(rsdt->table_offset_entry[i]));
		if (slic != NULL && memcmp(slic->signature, "SLIC", 4) == 0) {
			return slic;
		}
	}

	return NULL;
}

static void dump(u32 addr, u32 size, const char *line)
{
	u32 i = 0, j;
	if (debug >= 0) {
		return;
	}
	grub_printf("%s\n", line);
	for (i = 0; i < size; i += 16) {
		grub_printf("%08x: ", addr + i);
		for (j = 0; j < 16; ++j) {
			u32 v = addr + i + j;
			if (i + j < size) {
				grub_printf("%02x", *((u8 *) v));
			} else {
				grub_printf("  ", *((u8 *) v));
			}
			if (j & 1) {
				grub_printf(" ");
			}
		}
		grub_printf(" ");
		for (j = 0; j < 16; ++j) {
			u32 v = addr + i + j;
			char w = *((u8 *) v);
			if (i + j < size) {
				/* isprint(w) */
				grub_printf("%c", (w > 31 && w < 127) ? w : '.');
			} else {
				grub_printf(" ");
			}
		}
		grub_printf("\n");
	}
}

/**
 * strchr - Find the first occurrence of a character in a string
 * @s: The string to be searched
 * @c: The character to search for
 */
#define c d
#define strchr sc
static char *strchr(const char *s, int c)
{
	for (; *s != (char)c; ++s)
		if (*s == '\0')
			return NULL;
	return (char *)s;
}
#undef c

static int loadslic(char *arg, int flags)
{
	char *file = arg;
	struct acpi_table_header *slic;
	struct acpi_table_rsdp *rsdp;
	struct acpi_table_rsdt *rsdt, *new_rsdt;
	struct acpi_table_xsdt *xsdt, *new_xsdt;
	int rsdt_entries, xsdt_entries = 0;
	char buf[SLIC_LENGTH] = "\x53\x4c\x49\x43\x76\x01\x00\x00\x01\x45\x44\x45\x4c\x4c\x20\x20\x50\x45\x5f\x53\x43\x33\x20\x20\x01\x00\x00\x00\x44\x45\x4c\x4c\x00\x00\x04\x00\x00\x00\x00\x00\x9c\x00\x00\x00\x06\x02\x00\x00\x00\x24\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00\x01\x00\x01\x00\x7f\xf6\xc1\x05\xbe\x5c\x57\x63\xa5\x8a\x68\xf3\x6e\x8f\x06\xfa\xaf\xb4\x9f\x68\x82\x23\xec\x50\x40\x5a\x73\x7f\xec\xe4\x07\xcb\xdc\x25\x1a\x9c\xe3\xe3\x66\x11\xe0\xa5\x98\x06\xc5\x80\x0a\xfa\x42\x93\x86\x98\xe7\xd5\x1b\xd4\xd7\x3a\xa4\x0b\xee\xe2\x7d\xbe\x5f\x5b\x15\x0c\xab\xd0\x21\xde\xbf\xe9\xb5\x6e\xa4\x57\xb9\x8c\x0c\xd2\xba\x3a\x69\x30\x76\x94\x71\xa2\x64\xd7\x4c\xd8\x85\xbf\xdf\xa5\x6a\xc8\xdc\x45\xd5\x4d\x8c\xb8\x8c\x05\x2f\xfc\x2e\x23\xc4\x29\xc5\x6f\x3f\x29\x6c\x6d\x57\x79\x0e\xb6\x75\xed\x21\x95\x01\x00\x00\x00\xb6\x00\x00\x00\x00\x00\x02\x00\x44\x45\x4c\x4c\x20\x20\x50\x45\x5f\x53\x43\x33\x20\x20\x57\x49\x4e\x44\x4f\x57\x53\x20\x02\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x71\x0f\x95\x32\x81\xb5\x93\x75\x2f\x4f\x2a\xe0\x97\x43\x35\x96\x48\xe0\xaf\x2f\x16\x11\x8a\x70\x01\x93\x59\x01\xeb\x6b\x52\x66\x4d\x9c\x2e\xe7\x24\x8f\x82\x53\x61\xf8\xc5\x6c\x20\x8e\x9f\x63\xf5\xcf\x11\xb0\xac\x69\xdf\xc3\xad\x45\x41\x32\x4d\x89\x27\x54\x54\xc9\xf8\x91\x56\xd0\x05\xb7\xd6\x79\xe5\x0a\xbd\x19\x4c\x22\x75\x4b\x9d\x1f\xa8\x55\xd4\x93\x2c\x8d\x35\xfc\x5a\xe4\x1b\xc7\x61\x54\x43\xcb\xb7\x52\x2f\xcd\x09\x14\x47\x5b\x8d\x08\xbc\xbd\xb8\x2a\x3d\xa8\x4b\x49\x7c\x94\xbe\x3d\x60\x3e\xb7\xbc\x12\xf5";
	char slic_name[15] = "              ";
	u16 major, minor;

	rsdp = acpi_find_rsdp();
	if (rsdp == NULL) {
		grub_printf("can not find rsdp\n");
		return 1;
	}

	rsdt = (struct acpi_table_rsdt *)(rsdp->rsdt_physical_address);
	if (rsdt == NULL) {
		grub_printf("can not find rsdt\n");
		return 1;
	}
	rsdt_entries = (rsdt->header.length - sizeof(struct acpi_table_header)) / sizeof(u32);

	xsdt = (struct acpi_table_xsdt *)((u32) (rsdp->xsdt_physical_address));
	if (xsdt != NULL) {
		xsdt_entries = (xsdt->header.length - sizeof(struct acpi_table_header)) / sizeof(u64);
	}
	slic = acpi_find_slic(rsdt);
	if (debug < 0) {
		grub_printf("rsdt: %d, xsdt: %d, slic: %d\n", rsdt_entries, xsdt_entries, slic != NULL);
	}
	if (slic == NULL) {
		slic = (struct acpi_table_header *)acpi_get_mem(SLIC_LENGTH);
		if (slic == NULL) {
			grub_printf("cannot alloc memory for new slic\n");
			return 1;
		}

		new_rsdt = (struct acpi_table_rsdt *)acpi_get_mem(rsdt->header.length + sizeof(u32));
		if (new_rsdt == NULL) {
			grub_printf("cannot alloc memory for new rsdt\n");
			return 1;
		}
		grub_memcpy(new_rsdt, rsdt, rsdt->header.length);
		new_rsdt->header.length += sizeof(u32);
		new_rsdt->table_offset_entry[rsdt_entries] = (u32) slic;

		new_xsdt = (struct acpi_table_xsdt *)acpi_get_mem(xsdt->header.length + sizeof(u64));
		if (new_xsdt == NULL) {
			grub_printf("cannot alloc memory for new xsdt\n");
			return 1;
		}
		grub_memcpy(new_xsdt, xsdt, xsdt->header.length);
		new_xsdt->header.length += sizeof(u64);
		new_xsdt->table_offset_entry[xsdt_entries] = (u32) slic;

		/* try old rsdp */
		dump((u32) rsdp, rsdp->length, "old rsdp");
		rsdp->rsdt_physical_address = (u32) new_rsdt;
		rsdp->xsdt_physical_address = (u32) new_xsdt;
		dump((u32) rsdp, rsdp->length, "new rsdp");
		if (rsdp->rsdt_physical_address != (u32) new_rsdt || rsdp->xsdt_physical_address != (u32) new_xsdt) {
			/* rsdp must in rsdp area */
			struct acpi_table_rsdp *new_rsdp = (struct acpi_table_rsdp *)acpi_get_mem_rsdp(rsdp->length);
			if ((u32) new_rsdp == 0) {
				grub_printf("cannot alloc memory for new xsdt\n");
				return 1;
			}
			if ((u32) new_rsdp > (u32) rsdp) {
				grub_printf("cannot override rsdp\n");
				return 1;
			}
			grub_memcpy(new_rsdp, rsdp, rsdp->length);
			rsdp = new_rsdp;
			rsdp->rsdt_physical_address = (u32) new_rsdt;
			rsdp->xsdt_physical_address = (u32) new_xsdt;
		}
		rsdp->checksum = 0x0;
		rsdp->checksum = 1 + ~checksum((u8 *) rsdp, ACPI_RSDP_CHECKSUM_LENGTH);
		rsdp->extended_checksum = 0x0;
		rsdp->extended_checksum = 1 + ~checksum((u8 *) rsdp, ACPI_RSDP_XCHECKSUM_LENGTH);
		dump((u32) rsdp, rsdp->length, "end rsdp");
	} else {
		new_rsdt = rsdt;
		new_xsdt = xsdt;
	}

	if (slic == NULL) {
		grub_printf("can not find or generated slic\n");
		return 1;
	}

	if (*file != '\0') {
		if (!grub_open(file)) {
			grub_printf("grub open %s fail\n", file);
			return 1;
		}
		if (grub_read(buf, SLIC_LENGTH, 0xedde0d90) != SLIC_LENGTH) {
			grub_printf("grub read fail\n");
			grub_close();
			return 1;
		}
		grub_close();
	}

	grub_memcpy((char *)slic, buf, SLIC_LENGTH);

	if (grub_memcmp((char *)slic, buf, SLIC_LENGTH) != 0) {
		errnum = ERR_WONT_FIT;
		return 1;
	}

	grub_memcpy((char *)&(new_rsdt->header.oem_id), slic->oem_id, 6);
	grub_memcpy((char *)&(new_rsdt->header.oem_table_id), slic->oem_table_id, 8);
	if (debug < 0) {
		grub_printf("recalculating rsdt checksum: %d\n", new_rsdt->header.length);
	}
	new_rsdt->header.checksum = 0x0;
	new_rsdt->header.checksum = 1 + ~checksum((u8 *) new_rsdt, new_rsdt->header.length);
	dump((u32) new_rsdt, new_rsdt->header.length, "new rsdt");

	grub_memcpy((char *)&(new_xsdt->header.oem_id), slic->oem_id, 6);
	grub_memcpy((char *)&(new_xsdt->header.oem_table_id), slic->oem_table_id, 8);
	if (debug < 0) {
		grub_printf("recalculating xsdt checksum: %d\n", new_xsdt->header.length);
	}
	new_xsdt->header.checksum = 0x0;
	new_xsdt->header.checksum = 1 + ~checksum((u8 *) new_xsdt, new_xsdt->header.length);
	dump((u32) new_xsdt, new_xsdt->header.length, "new xsdt");

	dump((u32) slic, SLIC_LENGTH, "slic");

	grub_memcpy(slic_name, slic->oem_id, 6);
	grub_memcpy(strchr(slic_name, ' '), slic->oem_table_id, 8);
	grub_memcpy(strchr(slic_name, ' '), "", 1);
	memcpy(&minor, (char *)slic + 0xe2, 2);
	memcpy(&major, (char *)slic + 0xe4, 2);

	rsdp = acpi_find_rsdp();
	rsdt = (struct acpi_table_rsdt *)(rsdp->rsdt_physical_address);
	if ((u32) acpi_find_slic(rsdt) != (u32) slic) {
		return 1;
	} else if (*file != '\0') {
		grub_printf("loaded slic [%s_V%u.%u] from %s\n", slic_name, major, minor, file);
	} else {
		grub_printf("loaded slic [%s_V%u.%u]\n", slic_name, major, minor);
	}

	errnum = ERR_NONE;
	return 0;
}
