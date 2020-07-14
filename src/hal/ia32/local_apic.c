#include "apic.h"
#include "lib/lib.h"
#include "interrupts.h"
#include "spinlock.h"


static void lapic_writel(u32 reg, u32 value)
{
    *(volatile u32 *)(LAPIC_BASE + reg) = value;
}

static u32 lapic_readl(u32 reg)
{
    return *(volatile u32 *)(LAPIC_BASE + reg);
}

void lapic_eoi_msg()
{
    lapic_writel(LAPIC_EOI, 0);
}


static u32 lapic_get_id(void)
{
    u32 val, id;
    
    val = lapic_readl(LAPIC_ID);

    /* For now support just the xAPIC mode with 4 bit APIC ID */
    id = (val >> 24) & 0xf;
    return id;
}

/* 
 * Function for software, temporary enabling/disabling
 * a local APIC
 */
static void lapic_soft_enable(void)
{
    u32 value;

    value = lapic_readl(LAPIC_SVR);

    value &= ~(APIC_VECTOR_MASK | LAPIC_SVR_FOCUS_DISABLED);
    value |= LAPIC_SVR_FOCUS_ENABLED | LAPIC_SVR_ENABLED
            | APIC_SPURIOUS_INT;

    /* TODO EOI SUPPRESSION */
    lapic_writel(LAPIC_SVR, value);
}

static void lapic_soft_disable(void)
{
    u32 value;

    value = lapic_readl(LAPIC_SVR);
    value &= ~(LAPIC_SVR_ENABLED);

    lapic_writel(LAPIC_SVR, value);
}


static void lapic_setup_ldr_flat(u32 apic_id)
{
    u32 val;

    lapic_writel(LAPIC_DFR, LAPIC_DFR_MODEL_FLAT);
    val = lapic_readl(LAPIC_LDR);
    val &= ~LAPIC_LDR_MASK;
    val |= 1 << (apic_id + 24);
}

static void lapic_set_tpr(u32 vector)
{
    u32 tpr;

    tpr = lapic_readl(LAPIC_TPR);
    tpr &= ~LAPIC_TPR_PRIO_MASK;
    tpr |= vector;
    lapic_writel(LAPIC_TPR, tpr);
}

int lapic_timer_irq_handler(void)
{
    lib_printf("TIMER IRQ CPU: %x\n", lapic_get_id());
    threads_schedule();
    
    lib_printf("ACKED\n");

    return 0;
}


void lapic_ipi_send(u32 destination, u32 cmd)
{
    u32 val;

    val = lapic_readl(LAPIC_ICR + 0x10);
    val &= ~LAPIC_ICR_DEST_MASK;
    val |= destination << 24;
    lapic_writel(LAPIC_ICR + 0x10, val);

    val = lapic_readl(LAPIC_ICR);
    val &= ~LAPIC_ICR_LOW_MASK;
    val |= cmd;
    lapic_writel(LAPIC_ICR, val);
}

void lapic_timer_start(u32 init_cnt)
{

}


void lapic_setup(void)
{
    u32 val, apic_id;
    u8 version, max_lvt_entry, bsp;
    

    bsp = is_bsp();

    apic_id = lapic_get_id();
    val = lapic_readl(LAPIC_VERSION);

    version = val & LAPIC_VERSION_MASK;
    max_lvt_entry = LAPIC_MAX_LVT_ENTRY(val);


    /* For now stick with the flat model */
    lapic_setup_ldr_flat(apic_id);

    /* Allow all interrupts */
    lapic_set_tpr(0);

    lapic_soft_enable();

    /* Unmask the 8259A extINT for BSP only */
    if (bsp) {
        lapic_writel(LAPIC_LVT_LINT0, LAPIC_DELMOD_EXTINT);
    } else {
        lapic_writel(LAPIC_LVT_LINT0, LAPIC_IRQ_MASK |
                                  LAPIC_DELMOD_EXTINT);
    }

    /* Program LINT1 to deliver NMI to BSP only */
    val = LAPIC_DELMOD_EXTINT;

    if (!bsp)
        val |= LAPIC_IRQ_MASK;

    /* For 82489DX external APIC NMI is level triggered */
    if (version & 0x10 == 0)
        val |= LAPIC_TRIGMOD_LEVEL;
    lapic_writel(LAPIC_LVT_LINT1, val);

    /* TODO: handle APIC errors */
    /* Program Local APIC timer divisor */
    val = lapic_readl(LAPIC_TIMER_DCR);
    val &= ~LAPIC_TIMER_DCR_MASK;
    val |= LAPIC_TIMER_DIV_1;
    lapic_writel(LAPIC_TIMER_DCR, val);

    lib_printf("Enabling APIC\n");
    val = lapic_readl(LAPIC_LVT_TIMER);
    val &= ~LAPIC_LVT_TIMER_MASK;
    val |= LAPIC_TIMERMOD_PERIODIC | (32 + APIC_TIMER_INT);
    lapic_writel(LAPIC_LVT_TIMER, val);

    // /* Program Local APIC Initial Count */
    lapic_writel(LAPIC_TIMER_INIT_CNT, 100000000);

    lib_printf("LAPIC LVT TIMER: %x\n", lapic_readl(LAPIC_LVT_TIMER));
}

