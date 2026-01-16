# [Module 2.8] - Exercise 14: APIC & ACPI System Interfaces

## Metadonnees

```yaml
module: "2.8 - System Interfaces"
exercise: "ex14"
title: "APIC & ACPI Modern System Interfaces"
difficulty: expert
estimated_time: "6 heures"
prerequisite_exercises: ["ex13"]
concepts_requis: ["interrupts", "system tables", "SMP"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.8.25: APIC & Modern Interrupts (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.8.25.a | APIC | Advanced Programmable Interrupt Controller |
| 2.8.25.b | Local APIC | Per-CPU interrupt controller |
| 2.8.25.c | I/O APIC | External interrupt routing |
| 2.8.25.d | `x2apic` crate | APIC driver library |
| 2.8.25.e | MSR access | Model Specific Registers |
| 2.8.25.f | Timer | APIC local timer |
| 2.8.25.g | IPI | Inter-Processor Interrupt |
| 2.8.25.h | `acpi` crate | ACPI table parsing |
| 2.8.25.i | MADT | Multiple APIC Description Table |
| 2.8.25.j | SMP | Multi-processor support |

### 2.8.26: ACPI Tables (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.8.26.a | ACPI | Advanced Configuration and Power Interface |
| 2.8.26.b | RSDP | Root System Description Pointer |
| 2.8.26.c | RSDT/XSDT | Root System Description Tables |
| 2.8.26.d | MADT | Multiple APIC Description Table |
| 2.8.26.e | FADT | Fixed ACPI Description Table |
| 2.8.26.f | `acpi` crate | ACPI parsing library |
| 2.8.26.g | `AcpiTables::from_rsdp()` | Parse ACPI tables |
| 2.8.26.h | `tables.platform_info()` | Get system information |
| 2.8.26.i | Power management | Shutdown, sleep states |
| 2.8.26.j | `aml` crate | AML bytecode interpreter |

---

## Partie 1: Local APIC (2.8.25)

### Exercice 1.1: Local APIC Detection and Setup

**Cargo.toml:**

```toml
[dependencies]
x2apic = "0.4"
x86_64 = "0.14"
acpi = "5"
aml = "0.16"
```

**src/apic.rs:**

```rust
use x2apic::lapic::{LocalApic, LocalApicBuilder};
use x86_64::PhysAddr;

// APIC base address (default: 0xFEE00000)
const LAPIC_BASE: u64 = 0xFEE00000;

static mut LAPIC: Option<LocalApic> = None;

/// Check if APIC is available via CPUID
pub fn is_apic_available() -> bool {
    use core::arch::x86_64::__cpuid;

    let cpuid = unsafe { __cpuid(1) };
    // Check bit 9 of EDX (APIC present)
    (cpuid.edx & (1 << 9)) != 0
}

/// Check if x2APIC mode is available
pub fn is_x2apic_available() -> bool {
    use core::arch::x86_64::__cpuid;

    let cpuid = unsafe { __cpuid(1) };
    // Check bit 21 of ECX (x2APIC)
    (cpuid.ecx & (1 << 21)) != 0
}

/// Initialize the Local APIC
pub fn init() {
    if !is_apic_available() {
        panic!("APIC not available on this CPU");
    }

    crate::serial_println!("Initializing Local APIC...");
    crate::serial_println!("  x2APIC supported: {}", is_x2apic_available());

    let mut lapic = LocalApicBuilder::new()
        .timer_vector(48)      // Timer interrupt vector
        .error_vector(49)      // Error interrupt vector
        .spurious_vector(0xFF) // Spurious interrupt vector
        .set_xapic_base(LAPIC_BASE)
        .build()
        .expect("Failed to build LocalApic");

    unsafe {
        lapic.enable();
        LAPIC = Some(lapic);
    }

    crate::serial_println!("Local APIC initialized");
    crate::serial_println!("  APIC ID: {}", get_apic_id());
}

/// Get the Local APIC
pub fn get_lapic() -> &'static mut LocalApic {
    unsafe { LAPIC.as_mut().expect("LAPIC not initialized") }
}

/// Get the current CPU's APIC ID
pub fn get_apic_id() -> u32 {
    get_lapic().id()
}

/// Signal End of Interrupt
pub fn end_of_interrupt() {
    unsafe {
        get_lapic().end_of_interrupt();
    }
}
```

### Exercice 1.2: APIC Timer

```rust
use x2apic::lapic::{TimerDivide, TimerMode};

/// Initialize the APIC timer
pub fn init_timer(frequency_hz: u32) {
    let lapic = get_lapic();

    // Set timer divider
    lapic.set_timer_divide(TimerDivide::Div16);

    // Calibrate the timer to get the bus frequency
    let bus_freq = calibrate_timer();
    crate::serial_println!("  Bus frequency: {} Hz", bus_freq);

    // Calculate initial count for desired frequency
    let initial_count = bus_freq / 16 / frequency_hz;

    unsafe {
        lapic.set_timer_mode(TimerMode::Periodic);
        lapic.set_timer_initial(initial_count);
    }

    crate::serial_println!("APIC timer initialized: {} Hz", frequency_hz);
}

/// Calibrate the APIC timer using PIT
fn calibrate_timer() -> u32 {
    let lapic = get_lapic();

    // Set one-shot mode with maximum count
    unsafe {
        lapic.set_timer_mode(TimerMode::OneShot);
        lapic.set_timer_initial(0xFFFFFFFF);
    }

    // Use PIT to measure 10ms
    let pit_start = crate::timer::get_ticks();
    while crate::timer::get_ticks() < pit_start + 10 {
        core::hint::spin_loop();
    }

    // Read how much the APIC timer counted down
    let remaining = lapic.timer_current();
    let elapsed = 0xFFFFFFFF - remaining;

    // elapsed ticks in 10ms -> ticks per second
    let ticks_per_second = elapsed * 100;

    // Multiply by divider to get bus frequency
    ticks_per_second * 16
}

/// APIC timer interrupt handler
pub extern "x86-interrupt" fn apic_timer_handler(
    _stack_frame: x86_64::structures::idt::InterruptStackFrame
) {
    crate::timer::tick();
    end_of_interrupt();
}
```

### Exercice 1.3: Inter-Processor Interrupts (IPI)

```rust
use x2apic::ipi::{IpiDestination, IpiTriggerMode, IpiLevel, IpiDeliveryMode};

/// Send an IPI to a specific CPU
pub fn send_ipi(destination_apic_id: u32, vector: u8) {
    let lapic = get_lapic();

    unsafe {
        lapic.send_ipi(
            vector,
            IpiDestination::Physical(destination_apic_id),
            IpiDeliveryMode::Fixed,
            IpiTriggerMode::Edge,
            IpiLevel::Assert,
        );
    }

    crate::serial_println!("Sent IPI {} to CPU {}", vector, destination_apic_id);
}

/// Send an INIT IPI to start up another CPU
pub fn send_init_ipi(destination_apic_id: u32) {
    let lapic = get_lapic();

    unsafe {
        lapic.send_ipi(
            0,
            IpiDestination::Physical(destination_apic_id),
            IpiDeliveryMode::Init,
            IpiTriggerMode::Edge,
            IpiLevel::Assert,
        );
    }

    // Wait 10ms
    crate::timer::sleep_ms(10);

    // Deassert
    unsafe {
        lapic.send_ipi(
            0,
            IpiDestination::Physical(destination_apic_id),
            IpiDeliveryMode::Init,
            IpiTriggerMode::Level,
            IpiLevel::Deassert,
        );
    }
}

/// Send a STARTUP IPI to a CPU
pub fn send_startup_ipi(destination_apic_id: u32, vector: u8) {
    let lapic = get_lapic();

    // Send SIPI twice as recommended
    for _ in 0..2 {
        unsafe {
            lapic.send_ipi(
                vector,
                IpiDestination::Physical(destination_apic_id),
                IpiDeliveryMode::StartUp,
                IpiTriggerMode::Edge,
                IpiLevel::Assert,
            );
        }
        crate::timer::sleep_ms(1);
    }
}

/// Broadcast IPI to all CPUs except self
pub fn broadcast_ipi_all_excluding_self(vector: u8) {
    let lapic = get_lapic();

    unsafe {
        lapic.send_ipi(
            vector,
            IpiDestination::AllExcludingSelf,
            IpiDeliveryMode::Fixed,
            IpiTriggerMode::Edge,
            IpiLevel::Assert,
        );
    }
}
```

---

## Partie 2: I/O APIC

### Exercice 2.1: I/O APIC Setup

```rust
use x86_64::PhysAddr;
use volatile::Volatile;

const IOAPIC_BASE: u64 = 0xFEC00000;

// I/O APIC registers
const IOAPICID: u32 = 0x00;
const IOAPICVER: u32 = 0x01;
const IOAPICARB: u32 = 0x02;
const IOREDTBL_BASE: u32 = 0x10;

struct IoApic {
    address: *mut Volatile<u32>,
}

impl IoApic {
    unsafe fn new(base: u64) -> Self {
        IoApic {
            address: base as *mut Volatile<u32>,
        }
    }

    fn read(&self, register: u32) -> u32 {
        unsafe {
            // Write register index to IOREGSEL
            (*self.address).write(register);
            // Read from IOWIN (offset 0x10)
            let data_ptr = (self.address as u64 + 0x10) as *mut Volatile<u32>;
            (*data_ptr).read()
        }
    }

    fn write(&mut self, register: u32, value: u32) {
        unsafe {
            // Write register index to IOREGSEL
            (*self.address).write(register);
            // Write to IOWIN
            let data_ptr = (self.address as u64 + 0x10) as *mut Volatile<u32>;
            (*data_ptr).write(value);
        }
    }

    /// Get the I/O APIC ID
    fn id(&self) -> u8 {
        ((self.read(IOAPICID) >> 24) & 0xF) as u8
    }

    /// Get the maximum redirection entry
    fn max_redirection_entry(&self) -> u8 {
        ((self.read(IOAPICVER) >> 16) & 0xFF) as u8
    }

    /// Set a redirection entry
    fn set_irq(
        &mut self,
        irq: u8,
        vector: u8,
        destination_apic_id: u8,
        masked: bool,
    ) {
        let redirection_entry = (irq as u32) * 2 + IOREDTBL_BASE;

        // Low 32 bits: vector, delivery mode, destination mode, etc.
        let mut low = vector as u32;
        if masked {
            low |= 1 << 16; // Mask bit
        }

        // High 32 bits: destination APIC ID
        let high = (destination_apic_id as u32) << 24;

        self.write(redirection_entry, low);
        self.write(redirection_entry + 1, high);
    }

    /// Mask an IRQ
    fn mask_irq(&mut self, irq: u8) {
        let register = (irq as u32) * 2 + IOREDTBL_BASE;
        let low = self.read(register);
        self.write(register, low | (1 << 16));
    }

    /// Unmask an IRQ
    fn unmask_irq(&mut self, irq: u8) {
        let register = (irq as u32) * 2 + IOREDTBL_BASE;
        let low = self.read(register);
        self.write(register, low & !(1 << 16));
    }
}

static mut IOAPIC: Option<IoApic> = None;

pub fn init_ioapic(base: u64) {
    let ioapic = unsafe { IoApic::new(base) };

    crate::serial_println!("I/O APIC initialized:");
    crate::serial_println!("  ID: {}", ioapic.id());
    crate::serial_println!("  Max redirection entries: {}", ioapic.max_redirection_entry());

    unsafe { IOAPIC = Some(ioapic); }
}
```

---

## Partie 3: ACPI Tables (2.8.26)

### Exercice 3.1: Parsing ACPI Tables

```rust
use acpi::{AcpiTables, AcpiHandler, PhysicalMapping};
use core::ptr::NonNull;

#[derive(Clone)]
struct OdysseyAcpiHandler;

impl AcpiHandler for OdysseyAcpiHandler {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        // In our OS, physical memory is identity mapped
        // or we have a known offset
        let virtual_address = physical_address + PHYSICAL_MEMORY_OFFSET as usize;

        PhysicalMapping::new(
            physical_address,
            NonNull::new(virtual_address as *mut T).unwrap(),
            size,
            size,
            self.clone(),
        )
    }

    fn unmap_physical_region<T>(_region: &PhysicalMapping<Self, T>) {
        // Identity mapping, nothing to unmap
    }
}

const PHYSICAL_MEMORY_OFFSET: u64 = 0; // Adjust for your memory mapping

pub fn parse_acpi(rsdp_address: u64) -> acpi::AcpiTables<OdysseyAcpiHandler> {
    let handler = OdysseyAcpiHandler;

    unsafe {
        AcpiTables::from_rsdp(handler, rsdp_address as usize)
            .expect("Failed to parse ACPI tables")
    }
}

pub fn print_acpi_info(tables: &acpi::AcpiTables<OdysseyAcpiHandler>) {
    crate::serial_println!("ACPI Tables found:");

    // Get platform info (includes processor and interrupt info)
    if let Ok(platform_info) = tables.platform_info() {
        crate::serial_println!("  Boot processor: {:?}", platform_info.boot_processor);

        if let Some(processors) = &platform_info.application_processors {
            crate::serial_println!("  Application processors: {}", processors.len());
            for (i, proc) in processors.iter().enumerate() {
                crate::serial_println!("    AP {}: APIC ID {}", i, proc.local_apic_id);
            }
        }

        if let Some(interrupt_model) = &platform_info.interrupt_model {
            match interrupt_model {
                acpi::platform::interrupt::InterruptModel::Apic(apic_info) => {
                    crate::serial_println!("  Interrupt model: APIC");
                    crate::serial_println!("  Local APIC address: {:#x}",
                        apic_info.local_apic_address);
                    crate::serial_println!("  I/O APICs: {}", apic_info.io_apics.len());
                }
                _ => crate::serial_println!("  Interrupt model: Other"),
            }
        }
    }
}
```

### Exercice 3.2: MADT Parsing

```rust
use acpi::madt::Madt;
use acpi::platform::interrupt::Apic;

pub struct ApicInfo {
    pub local_apic_address: u64,
    pub io_apic_address: u64,
    pub processor_local_apics: alloc::vec::Vec<LocalApicInfo>,
}

pub struct LocalApicInfo {
    pub acpi_processor_id: u8,
    pub apic_id: u8,
    pub is_enabled: bool,
}

pub fn parse_madt(tables: &acpi::AcpiTables<OdysseyAcpiHandler>) -> Option<ApicInfo> {
    let platform_info = tables.platform_info().ok()?;
    let interrupt_model = platform_info.interrupt_model.as_ref()?;

    match interrupt_model {
        acpi::platform::interrupt::InterruptModel::Apic(apic) => {
            let mut info = ApicInfo {
                local_apic_address: apic.local_apic_address,
                io_apic_address: apic.io_apics.first()?.address as u64,
                processor_local_apics: alloc::vec::Vec::new(),
            };

            // Add boot processor
            info.processor_local_apics.push(LocalApicInfo {
                acpi_processor_id: platform_info.boot_processor.as_ref()?.processor_uid as u8,
                apic_id: platform_info.boot_processor.as_ref()?.local_apic_id as u8,
                is_enabled: true,
            });

            // Add application processors
            if let Some(ap_list) = &platform_info.application_processors {
                for ap in ap_list {
                    info.processor_local_apics.push(LocalApicInfo {
                        acpi_processor_id: ap.processor_uid as u8,
                        apic_id: ap.local_apic_id as u8,
                        is_enabled: ap.state == acpi::platform::ProcessorState::WaitingForSipi,
                    });
                }
            }

            Some(info)
        }
        _ => None,
    }
}
```

### Exercice 3.3: Power Management with ACPI

```rust
use x86_64::instructions::port::Port;

/// ACPI power states
pub enum AcpiState {
    S0,  // Working
    S1,  // Sleeping (CPU stops, RAM refreshed)
    S3,  // Suspend to RAM
    S4,  // Suspend to disk (hibernate)
    S5,  // Soft off
}

/// Shutdown the system using ACPI
pub fn shutdown() {
    // ACPI shutdown requires finding the PM1a_CNT register from FADT
    // and writing the SLP_TYP and SLP_EN bits

    // For QEMU with -device isa-debug-exit
    unsafe {
        let mut port = Port::<u32>::new(0xf4);
        port.write(0x10);
    }

    // Generic ACPI shutdown for real hardware (simplified)
    // Would need to read FADT to get correct ports
    crate::serial_println!("Attempting ACPI shutdown...");

    // Try common ACPI shutdown ports
    unsafe {
        // QEMU/Bochs
        let mut pm1a = Port::<u16>::new(0x604);
        pm1a.write(0x2000);

        // VirtualBox
        let mut pm1a_vbox = Port::<u16>::new(0x4004);
        pm1a_vbox.write(0x3400);
    }

    crate::serial_println!("Shutdown failed, halting...");
    crate::hlt_loop();
}

/// Reboot the system
pub fn reboot() {
    crate::serial_println!("Rebooting...");

    // Method 1: Keyboard controller reset
    unsafe {
        let mut port = Port::<u8>::new(0x64);
        while port.read() & 0x02 != 0 {
            core::hint::spin_loop();
        }
        port.write(0xFE);
    }

    // Method 2: Triple fault (last resort)
    unsafe {
        x86_64::instructions::interrupts::disable();
        // Load invalid IDT
        let null_idt = x86_64::structures::idt::InterruptDescriptorTable::new();
        null_idt.load_unsafe();
        // Trigger interrupt
        core::arch::asm!("int3", options(nomem, nostack));
    }

    crate::hlt_loop();
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Local APIC setup | 20 |
| APIC timer | 15 |
| IPI implementation | 15 |
| I/O APIC | 15 |
| ACPI table parsing | 20 |
| Power management | 15 |
| **Total** | **100** |

---

## Ressources

- [x2apic crate docs](https://docs.rs/x2apic/)
- [acpi crate docs](https://docs.rs/acpi/)
- [OSDev Wiki: APIC](https://wiki.osdev.org/APIC)
- [OSDev Wiki: ACPI](https://wiki.osdev.org/ACPI)
- [Intel SDM Volume 3](https://www.intel.com/sdm)
