/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <defs.h>
#include <boot.h>
#include <types.h>
#include <string.h>
#include <tags.h>
#include <sha256.h>
#include <pci.h>
#include <iommu.h>
#include <printk.h>

#define DEVICE_TABLE_SIZE (2 * PAGE_SIZE / sizeof(iommu_dte_t))

iommu_dte_t device_table[DEVICE_TABLE_SIZE] __page_data = {
    [0 ... ARRAY_SIZE(device_table) - 1 ] = {
        .a = IOMMU_DTE_Q0_V + IOMMU_DTE_Q0_TV,
    },
};
iommu_dte_t *device_table_ptr = &device_table[0];

iommu_command_t command_buf[2] __aligned(sizeof(iommu_command_t));
iommu_command_t *command_buf_ptr = &command_buf[0];

char event_log[PAGE_SIZE] __page_data;
char *event_log_ptr = &event_log[0];

#ifdef METHOD2
static u8 cmd_buffer_hash[SHA256_DIGEST_SIZE];
static u8 device_table_hash[SHA256_DIGEST_SIZE];
#endif

static void send_command(u64 *mmio_base, iommu_command_t cmd)
{
    u32 cmd_ptr = mmio_base[IOMMU_MMIO_COMMAND_BUF_TAIL] >> 4;
    command_buf_ptr[cmd_ptr++] = cmd;
    smp_wmb();
#ifdef METHOD2
    if ( cmd.opcode == INVALIDATE_IOMMU_ALL )
    {
        /* Hash command buffer and device table before sending command */
        sha256sum(cmd_buffer_hash, command_buf_ptr,
                  2*sizeof(iommu_command_t));
        sha256sum(device_table_hash, device_table_ptr,
                  DEVICE_TABLE_SIZE);
    }
#endif
    mmio_base[IOMMU_MMIO_COMMAND_BUF_TAIL] = (cmd_ptr << 4);
}

static u32 iommu_load_device_table(u64 *mmio_base, volatile u64 *completed)
{
    iommu_command_t cmd = {0};

    print("IOMMU MMIO Base Address = ");
    print_u64((u64)_u(mmio_base));
    print("\n");

    print_u64(mmio_base[IOMMU_MMIO_STATUS_REGISTER]);
    print("IOMMU_MMIO_STATUS_REGISTER\n");

    /* Disable IOMMU and all its features */
    mmio_base[IOMMU_MMIO_CONTROL_REGISTER] &= ~IOMMU_CR_ENABLE_ALL_MASK;
    smp_wmb();

    /* Address and size of Device Table (bits 8:0 = 0 -> 4KB; 1 -> 8KB ...) */
    mmio_base[IOMMU_MMIO_DEVICE_TABLE_BA] = (u64)_u(device_table_ptr) | 1;

    print_u64(mmio_base[IOMMU_MMIO_DEVICE_TABLE_BA]);
    print("IOMMU_MMIO_DEVICE_TABLE_BA\n");

    /*
     * !!! WARNING - HERE BE DRAGONS !!!
     *
     * Address and size of Command Buffer, reset head and tail registers.
     *
     * The IOMMU command buffer is required to be an aligned power of two,
     * with a minimum size of 4k.  We only need to send a handful of
     * commands, and really don't have 4k worth of space to spare.
     * Furthermore, the buffer is only ever read by the IOMMU.
     *
     * Therefore, we have a small array of command buffer entries, aligned
     * on the size of one entry.  We program the IOMMU to say that the
     * command buffer is 8k long (to cover the case that the array crosses
     * a page boundary), and move both the head and tail pointers forwards
     * to the start of the buffer.
     *
     * This will malfunction if more commands are sent than fit in
     * command_buf[] to begin with, but we do save almost 4k of space,
     * 1/16th of that available to us.
     */
    mmio_base[IOMMU_MMIO_COMMAND_BUF_BA] = (u64)(_u(command_buf_ptr) & ~0xfff)| (0x9ULL << 56);
    mmio_base[IOMMU_MMIO_COMMAND_BUF_HEAD] =
        mmio_base[IOMMU_MMIO_COMMAND_BUF_TAIL] = _u(command_buf_ptr) & 0xff0;

    print_u64(mmio_base[IOMMU_MMIO_COMMAND_BUF_BA]);
    print("IOMMU_MMIO_COMMAND_BUF_BA\n");

    /* Address and size of Event Log, reset head and tail registers */
    mmio_base[IOMMU_MMIO_EVENT_LOG_BA] = (u64)_u(event_log_ptr) | (0x8ULL << 56);
    mmio_base[IOMMU_MMIO_EVENT_LOG_HEAD] = 0;
    mmio_base[IOMMU_MMIO_EVENT_LOG_TAIL] = 0;

    print_u64(mmio_base[IOMMU_MMIO_EVENT_LOG_BA]);
    print("IOMMU_MMIO_EVENT_LOG_BA\n");

    /* Clear EventLogInt set by IOMMU not being able to read command buffer */
    mmio_base[IOMMU_MMIO_STATUS_REGISTER] &= ~2;
    smp_wmb();
    mmio_base[IOMMU_MMIO_CONTROL_REGISTER] |= IOMMU_CR_CmdBufEn | IOMMU_CR_EventLogEn;
    smp_wmb();

    mmio_base[IOMMU_MMIO_CONTROL_REGISTER] |= IOMMU_CR_IommuEn;

    print_u64(mmio_base[IOMMU_MMIO_STATUS_REGISTER]);
    print("IOMMU_MMIO_STATUS_REGISTER\n");

    if ( mmio_base[IOMMU_MMIO_EXTENDED_FEATURE] & IOMMU_EF_IASup )
    {
        print("INVALIDATE_IOMMU_ALL\n");
        cmd.opcode = INVALIDATE_IOMMU_ALL;
        send_command(mmio_base, cmd);
    } /* TODO: else? */

    print_u64(mmio_base[IOMMU_MMIO_EXTENDED_FEATURE]);
    print("IOMMU_MMIO_EXTENDED_FEATURE\n");
    print_u64(mmio_base[IOMMU_MMIO_STATUS_REGISTER]);
    print("IOMMU_MMIO_STATUS_REGISTER\n");

    /* Write to a variable inside SLB (does not work in the first call) */
    cmd.u0 = _u(completed) | 1;
    /* This should be '_u(completed)>>32', but SLB can't be above 4GB anyway */
    cmd.u1 = 0;

    cmd.opcode = COMPLETION_WAIT;
    cmd.u2 = 0x656e6f64;    /* "done" */
    send_command(mmio_base, cmd);

    print_u64(mmio_base[IOMMU_MMIO_STATUS_REGISTER]);
    print("IOMMU_MMIO_STATUS_REGISTER\n");

    return 0;
}

#ifdef TEST_DMA
static void do_dma(void)
{
    /* Set up the DMA channel so we can use it.  This tells the DMA */
    /* that we're going to be using this channel.  (It's masked) */
    outb(0x0a, 0x05);

    /* Clear any data transfers that are currently executing. */
    outb(0x0c, 0x00);

    /* Send the specified mode to the DMA. */
    outb(0x0b, 0x45);

    /* Send the offset address.  The first byte is the low base offset, the */
    /* second byte is the high offset. */
    //~ outportb(AddrPort[DMA_channel], LOW_BYTE(blk->offset));
    //~ outportb(AddrPort[DMA_channel], HI_BYTE(blk->offset));
    outb(0x02, 0x00);
    outb(0x02, 0x00);

    /* Send the physical page that the data lies on. */
    //~ outportb(PagePort[DMA_channel], blk->page);
    outb(0x83, 0x00);

    /* Send the length of the data.  Again, low byte first. */
    //~ outportb(CountPort[DMA_channel], LOW_BYTE(blk->length));
    //~ outportb(CountPort[DMA_channel], HI_BYTE(blk->length));
    outb(0x03, 0x20);
    outb(0x03, 0x00);

    /* Ok, we're done.  Enable the DMA channel (clear the mask). */
    //~ outportb(MaskReg[DMA_channel], DMA_channel);
    outb(0x0a, 0x01);

    // "Device" says that it is ready to send data. As there is no device
    // physically sending the data, this reads idle bus lines.
    outb(0x09, 0x05);
}
#endif

#ifdef METHOD1
static u32 iommu_locate_cap(void)
{
    return pci_locate(IOMMU_PCI_BUS,
                      PCI_DEVFN(IOMMU_PCI_DEVICE, IOMMU_PCI_FUNCTION));
}

static u64 *iommu_locate_bar(u32 cap)
{
    u32 low, hi;

    pci_read(0, IOMMU_PCI_BUS,
             PCI_DEVFN(IOMMU_PCI_DEVICE, IOMMU_PCI_FUNCTION),
             IOMMU_CAP_BA_LOW(cap),
             4, &low);

    /* IOMMU must be enabled by AGESA */
    if ( (low & IOMMU_CAP_BA_LOW_ENABLE) == 0 )
        return NULL;

    pci_read(0, IOMMU_PCI_BUS,
             PCI_DEVFN(IOMMU_PCI_DEVICE, IOMMU_PCI_FUNCTION),
             IOMMU_CAP_BA_HIGH(cap),
             4, &hi);

    return _p((u64)hi << 32 | (low & 0xffffc000));
}

void iommu_setup_method1(void)
{
    u32 iommu_cap;
    u64 *mmio_base;
    volatile u64 iommu_done __attribute__ ((aligned (8))) = 0;

#ifdef TEST_DMA
    memset(_p(1), 0xcc, 0x20); //_p(0) gives a null-pointer error
    print("before DMA:\n");
    hexdump(_p(0), 0x30);
    do_dma();
    /* Important line, it delays hexdump */
    print("after DMA:              \n");
    hexdump(_p(0), 0x30);
    memset(_p(1), 0xcc, 0x20);
    print("before DMA2\n");
    hexdump(_p(0), 0x30);
    do_dma();
    /* Important line, it delays hexdump */
    print("after DMA2              \n");
    hexdump(_p(0), 0x30);
#endif

    pci_init();
    iommu_cap = iommu_locate_cap();
    if ( !iommu_cap )
    {
        print("Failed to locate IOMMU device and capabilities\n");
        return;
    }

    mmio_base = iommu_locate_bar(iommu_cap);
    if ( !mmio_base )
    {
        print("IOMMU disabled by a firmware, please check your settings\n");
        print("Couldn't set up IOMMU, DMA attacks possible!\n");
        return;
    }

    /*
     * SKINIT enables protection against DMA access from devices for SLB
     * (whole 64K, not just the measured part). This ensures that no device
     * can overwrite code or data of SL. Unfortunately, it also means that
     * IOMMU, being a PCI device, also cannot read from this memory region.
     * When IOMMU is trying to read a command from buffer located in SLB it
     * receives COMMAND_HARDWARE_ERROR (master abort).
     *
     * Luckily, after that error it enters a fail-safe state in which all
     * operations originating from devices are blocked. The IOMMU itself can
     * still access the memory, so after the SLB protection is lifted, it can
     * try to read the data located inside SLB and set up a proper protection.
     *
     * TODO: split iommu_load_device_table() into two parts, before and after
     *       DEV disabling
     *
     * TODO2: check if IOMMU always blocks the devices, even when it was
     *        configured before SKINIT
     */

    if ( iommu_load_device_table(mmio_base, &iommu_done) )
    {
        print("Failed initial device table load, DMA attacks possible!\n");
    }
    else
    {
        /* Turn off SLB protection, try again */
        print("Disabling SLB protection\n");
        disable_memory_protection();

#ifdef TEST_DMA
        memset(_p(1), 0xcc, 0x20);
        print("before DMA:\n");
        hexdump(_p(0), 0x30);
        do_dma();
        /* Important line, it delays hexdump */
        print("after DMA:              \n");
        hexdump(_p(0), 0x30);
        /* Important line, it delays hexdump */
        print("and again\n");
        hexdump(_p(0), 0x30);

        memset(_p(1), 0xcc, 0x20);
        print("before DMA2\n");
        hexdump(_p(0), 0x30);
        do_dma();
        /* Important line, it delays hexdump */
        print("after DMA2              \n");
        hexdump(_p(0), 0x30);
        /* Important line, it delays hexdump */
        print("and again2\n");
        hexdump(_p(0), 0x30);
#endif

        iommu_load_device_table(mmio_base, &iommu_done);
        print("Flushing IOMMU cache");
        while ( !iommu_done )
            print(".");

        print("\nIOMMU set\n");
    }

#ifdef TEST_DMA
    memset(_p(1), 0xcc, 0x20);
    print("before DMA:\n");
    hexdump(_p(0), 0x30);
    do_dma();
    /* Important line, it delays hexdump */
    print("after DMA:              \n");
    hexdump(_p(0), 0x30);
    /* Important line, it delays hexdump */
    print("and again\n");
    hexdump(_p(0), 0x30);

    memset(_p(1), 0xcc, 0x20);
    print("before DMA2\n");
    hexdump(_p(0), 0x30);
    do_dma();
    /* Important line, it delays hexdump */
    print("after DMA2              \n");
    hexdump(_p(0), 0x30);
    /* Important line, it delays hexdump */
    print("and again2\n");
    hexdump(_p(0), 0x30);
#endif
}
#else
static u8 cmd_buffer_rehash[SHA256_DIGEST_SIZE];
static u8 device_table_rehash[SHA256_DIGEST_SIZE];

static void __attribute__((noreturn)) terminate(void)
{
    print("Possible attack detected, reseting system now!");
    die();
    unreachable();
}

void iommu_setup_method2(void)
{
    struct skl_tag_hdr *t = (struct skl_tag_hdr*) &bootloader_data;
    struct skl_tag_iommu_info *iommu_info;
    volatile u64 *iommu_done;
    struct skl_ivhd_entry *ivhd;
    u64 *mmio_base;
    u64 mmio_val;
    u32 i;

    iommu_info = (struct skl_tag_iommu_info *)next_of_type(t, SKL_TAG_IOMMU_INFO);
    if ( iommu_info->hdr.type   != SKL_TAG_IOMMU_INFO
         || iommu_info->hdr.len != sizeof(struct skl_tag_iommu_info) )
    {
        print("Invalid IOMMU information provided, cannot configure IOMMU\n");
        return;
    }

    if ( !iommu_info->count )
    {
        print("No IOMMU hardware devices present\n");
        return;
    }

    /*
     * Copy the device table, event log and command buffer outside of the
     * SKL and the exclusion zone. There is no way currently to disable the
     * exclusion zone on Milan/Rome gen servers. That is why a separate
     * method is required to configure the IOMMU.
     */
    if ( iommu_info->dma_area_size <
        DEVICE_TABLE_SIZE + PAGE_SIZE + 2*sizeof(iommu_command_t) + sizeof(u64) )
    {
        print("IOMMU DMA area too small, cannot setup IOMMU\n");
        return;
    }
    memset(_p(iommu_info->dma_area_addr), 0, iommu_info->dma_area_size);
    memcpy(_p(iommu_info->dma_area_addr), &device_table[0], DEVICE_TABLE_SIZE);
    device_table_ptr = (iommu_dte_t *)_u(iommu_info->dma_area_addr);
    event_log_ptr = (char *)(_u(iommu_info->dma_area_addr) + DEVICE_TABLE_SIZE);
    command_buf_ptr = (iommu_command_t *)(_u(iommu_info->dma_area_addr) +
                                          DEVICE_TABLE_SIZE + PAGE_SIZE);
    /* Note iommu_done will end up 8b aligned in the end */
    iommu_done = (u64 *)(_u(iommu_info->dma_area_addr) + DEVICE_TABLE_SIZE +
                         PAGE_SIZE + 2*sizeof(iommu_command_t));

    ivhd = (struct skl_ivhd_entry *)
           ((u8 *)iommu_info + sizeof(struct skl_tag_iommu_info));

    for ( i = 0; i < iommu_info->count; i++, ivhd++)
    {
        print("IOMMU Device ID = ");
        print_u64((u64)ivhd->device_id);
        print("\n");

        /* IOMMU must be enabled by AGESA */
        if ( (ivhd->base_address & IOMMU_CAP_BA_LOW_ENABLE) == 0 )
        {
            print("IOMMU disabled by a firmware, please check your settings\n");
            print("Couldn't set up IOMMU, DMA attacks possible!\n");
            continue;
        }

        mmio_val = ivhd->base_address & 0xffffffffffffc000;
        mmio_base = _p(mmio_val);

        /* Setup new device table for this IOMMU */
        iommu_load_device_table(mmio_base, iommu_done);

        while ( !(*iommu_done) )
            print(".");

        /* Rehash command buffer and device table after completion */
        sha256sum(cmd_buffer_rehash, command_buf_ptr,
                  2*sizeof(iommu_command_t));
        sha256sum(device_table_rehash, device_table_ptr,
                  DEVICE_TABLE_SIZE);

        if ( memcmp(cmd_buffer_hash, cmd_buffer_rehash, SHA256_DIGEST_SIZE) ||
             memcmp(device_table_hash, device_table_rehash, SHA256_DIGEST_SIZE) )
            terminate();
    }
}
#endif
