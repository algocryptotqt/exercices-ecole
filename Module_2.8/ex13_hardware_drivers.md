# [Module 2.8] - Exercise 13: Hardware Drivers in Rust

## Metadonnees

```yaml
module: "2.8 - System Interfaces"
exercise: "ex13"
title: "Keyboard and Timer Drivers"
difficulty: expert
estimated_time: "5 heures"
prerequisite_exercises: ["ex00", "ex08"]
concepts_requis: ["interrupts", "I/O ports", "hardware"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.8.23: Keyboard Driver in Rust (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.8.23.a | `pc-keyboard` crate | Keyboard driver library |
| 2.8.23.b | PS/2 controller | Ports 0x60, 0x64 |
| 2.8.23.c | IRQ 1 | Keyboard interrupt |
| 2.8.23.d | `Keyboard::new()` | Create keyboard instance |
| 2.8.23.e | `keyboard.add_byte(scancode)` | Feed scancode to decoder |
| 2.8.23.f | `keyboard.process_keyevent()` | Get decoded key event |
| 2.8.23.g | `DecodedKey` | Unicode or RawKey output |
| 2.8.23.h | Scancode sets | Set 1, Set 2 formats |
| 2.8.23.i | Layouts | US, UK, DE, FR keyboard layouts |
| 2.8.23.j | Modifier keys | Shift, Ctrl, Alt handling |

### 2.8.24: Timer (PIT) in Rust (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.8.24.a | PIT | Programmable Interval Timer |
| 2.8.24.b | Base frequency | 1.193182 MHz crystal |
| 2.8.24.c | IRQ 0 | Timer interrupt |
| 2.8.24.d | Ports | 0x40-0x43 I/O ports |
| 2.8.24.e | Channel 0 | System timer channel |
| 2.8.24.f | Divider | Setting tick rate |
| 2.8.24.g | `AtomicU64` | Tick counter storage |
| 2.8.24.h | Handler | Timer interrupt handler |
| 2.8.24.i | `pic8259` crate | PIC interrupt controller |
| 2.8.24.j | End of interrupt | `pics.notify_end_of_interrupt()` |

---

## Partie 1: Keyboard Driver (2.8.23)

### Exercice 1.1: Basic Keyboard Setup

**Cargo.toml dependencies:**

```toml
[dependencies]
pc-keyboard = "0.7"
x86_64 = "0.14"
spin = "0.9"
lazy_static = { version = "1.4", features = ["spin_no_std"] }
```

**src/keyboard.rs:**

```rust
use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};
use spin::Mutex;
use x86_64::instructions::port::Port;
use lazy_static::lazy_static;

lazy_static! {
    static ref KEYBOARD: Mutex<Keyboard<layouts::Us104Key, ScancodeSet1>> =
        Mutex::new(Keyboard::new(
            ScancodeSet1::new(),
            layouts::Us104Key,
            HandleControl::Ignore,
        ));
}

pub const PS2_DATA_PORT: u16 = 0x60;
pub const PS2_STATUS_PORT: u16 = 0x64;

/// Read a scancode from the PS/2 data port
pub fn read_scancode() -> u8 {
    let mut port = Port::<u8>::new(PS2_DATA_PORT);
    unsafe { port.read() }
}

/// Check if data is available in the PS/2 controller
pub fn data_available() -> bool {
    let mut port = Port::<u8>::new(PS2_STATUS_PORT);
    let status = unsafe { port.read() };
    status & 0x01 != 0
}

/// Process a scancode and return the decoded key if available
pub fn process_scancode(scancode: u8) -> Option<DecodedKey> {
    let mut keyboard = KEYBOARD.lock();

    // Add the scancode byte to the keyboard decoder
    if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
        // Process the key event and get the decoded key
        keyboard.process_keyevent(key_event)
    } else {
        None
    }
}

/// Keyboard interrupt handler
pub fn handle_keyboard_interrupt() {
    let scancode = read_scancode();

    if let Some(key) = process_scancode(scancode) {
        match key {
            DecodedKey::Unicode(character) => {
                crate::print!("{}", character);
            }
            DecodedKey::RawKey(key) => {
                crate::print!("{:?}", key);
            }
        }
    }
}
```

### Exercice 1.2: Keyboard with Different Layouts

```rust
use pc_keyboard::{layouts, Keyboard, ScancodeSet1, ScancodeSet2, HandleControl};

// US QWERTY layout
fn create_us_keyboard() -> Keyboard<layouts::Us104Key, ScancodeSet1> {
    Keyboard::new(
        ScancodeSet1::new(),
        layouts::Us104Key,
        HandleControl::Ignore,
    )
}

// UK layout
fn create_uk_keyboard() -> Keyboard<layouts::Uk105Key, ScancodeSet1> {
    Keyboard::new(
        ScancodeSet1::new(),
        layouts::Uk105Key,
        HandleControl::Ignore,
    )
}

// German layout
fn create_de_keyboard() -> Keyboard<layouts::De105Key, ScancodeSet1> {
    Keyboard::new(
        ScancodeSet1::new(),
        layouts::De105Key,
        HandleControl::Ignore,
    )
}

// French AZERTY layout
fn create_fr_keyboard() -> Keyboard<layouts::Azerty, ScancodeSet1> {
    Keyboard::new(
        ScancodeSet1::new(),
        layouts::Azerty,
        HandleControl::Ignore,
    )
}

// Scancode Set 2 (modern keyboards)
fn create_set2_keyboard() -> Keyboard<layouts::Us104Key, ScancodeSet2> {
    Keyboard::new(
        ScancodeSet2::new(),
        layouts::Us104Key,
        HandleControl::MapLettersToUnicode,  // Handle Ctrl differently
    )
}
```

### Exercice 1.3: Modifier Keys and Special Keys

```rust
use pc_keyboard::{KeyCode, KeyState, KeyEvent, DecodedKey};

pub struct KeyboardState {
    shift_pressed: bool,
    ctrl_pressed: bool,
    alt_pressed: bool,
    caps_lock: bool,
}

impl KeyboardState {
    pub fn new() -> Self {
        KeyboardState {
            shift_pressed: false,
            ctrl_pressed: false,
            alt_pressed: false,
            caps_lock: false,
        }
    }

    pub fn handle_key_event(&mut self, event: KeyEvent) -> Option<char> {
        match event.code {
            KeyCode::LShift | KeyCode::RShift => {
                self.shift_pressed = event.state == KeyState::Down;
                None
            }
            KeyCode::LControl | KeyCode::RControl => {
                self.ctrl_pressed = event.state == KeyState::Down;
                None
            }
            KeyCode::LAlt | KeyCode::RAlt => {
                self.alt_pressed = event.state == KeyState::Down;
                None
            }
            KeyCode::CapsLock if event.state == KeyState::Down => {
                self.caps_lock = !self.caps_lock;
                None
            }
            _ if event.state == KeyState::Down => {
                // Handle special key combinations
                if self.ctrl_pressed {
                    self.handle_ctrl_combo(event.code)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn handle_ctrl_combo(&self, code: KeyCode) -> Option<char> {
        match code {
            KeyCode::C => {
                crate::println!("^C - Interrupt");
                Some('\x03')
            }
            KeyCode::D => {
                crate::println!("^D - EOF");
                Some('\x04')
            }
            KeyCode::L => {
                // Clear screen
                crate::vga_buffer::WRITER.lock().clear_screen();
                Some('\x0C')
            }
            _ => None,
        }
    }
}
```

---

## Partie 2: Timer Driver (2.8.24)

### Exercice 2.1: PIT Timer Setup

```rust
use x86_64::instructions::port::Port;
use core::sync::atomic::{AtomicU64, Ordering};

// PIT ports
const PIT_CHANNEL_0: u16 = 0x40;
const PIT_CHANNEL_1: u16 = 0x41;
const PIT_CHANNEL_2: u16 = 0x42;
const PIT_COMMAND: u16 = 0x43;

// PIT base frequency: 1.193182 MHz
const PIT_FREQUENCY: u32 = 1_193_182;

// Desired timer frequency (e.g., 1000 Hz = 1ms resolution)
const TIMER_FREQUENCY: u32 = 1000;

// Global tick counter
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Initialize the PIT to generate interrupts at the desired frequency
pub fn init_pit(frequency: u32) {
    // Calculate the divider
    let divider = PIT_FREQUENCY / frequency;

    // Ensure divider fits in 16 bits
    let divider = if divider > 65535 { 65535 } else { divider as u16 };

    // Command byte: Channel 0, lobyte/hibyte, rate generator, binary mode
    let command: u8 = 0b00_11_010_0;
    //                   || || ||| |
    //                   || || ||| +- Binary mode (not BCD)
    //                   || || +++--- Rate generator (mode 2)
    //                   || ++------- Access mode: lobyte/hibyte
    //                   ++---------- Channel 0

    unsafe {
        let mut cmd_port = Port::<u8>::new(PIT_COMMAND);
        let mut data_port = Port::<u8>::new(PIT_CHANNEL_0);

        // Send command
        cmd_port.write(command);

        // Send divider (low byte first, then high byte)
        data_port.write((divider & 0xFF) as u8);
        data_port.write((divider >> 8) as u8);
    }

    crate::serial_println!("PIT initialized: {} Hz (divider: {})", frequency, divider);
}

/// Get the current tick count
pub fn get_ticks() -> u64 {
    TICKS.load(Ordering::SeqCst)
}

/// Increment the tick counter (called from timer interrupt handler)
pub fn tick() {
    TICKS.fetch_add(1, Ordering::SeqCst);
}

/// Sleep for approximately the given number of milliseconds
pub fn sleep_ms(ms: u64) {
    let target = get_ticks() + ms;
    while get_ticks() < target {
        x86_64::instructions::hlt();
    }
}

/// Get uptime in seconds
pub fn uptime_seconds() -> u64 {
    get_ticks() / TIMER_FREQUENCY as u64
}
```

### Exercice 2.2: Timer Interrupt Handler

**src/interrupts.rs:**

```rust
use x86_64::structures::idt::InterruptStackFrame;
use crate::timer;
use crate::PICS;

// Timer interrupt index (IRQ 0 -> interrupt 32)
pub const TIMER_INTERRUPT_INDEX: u8 = 32;

pub extern "x86-interrupt" fn timer_interrupt_handler(
    _stack_frame: InterruptStackFrame
) {
    // Increment the tick counter
    timer::tick();

    // Optionally: print a dot every second
    #[cfg(debug_assertions)]
    {
        static mut LAST_SECOND: u64 = 0;
        let current_second = timer::uptime_seconds();
        unsafe {
            if current_second != LAST_SECOND {
                LAST_SECOND = current_second;
                crate::serial_print!(".");
            }
        }
    }

    // Signal end of interrupt to the PIC
    unsafe {
        PICS.lock().notify_end_of_interrupt(TIMER_INTERRUPT_INDEX);
    }
}
```

### Exercice 2.3: High-Resolution Timer with TSC

```rust
use core::sync::atomic::{AtomicU64, Ordering};

static TSC_FREQUENCY: AtomicU64 = AtomicU64::new(0);

/// Read the Time Stamp Counter
#[inline]
pub fn read_tsc() -> u64 {
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
}

/// Calibrate TSC frequency using PIT
pub fn calibrate_tsc() {
    let pit_start = crate::timer::get_ticks();
    let tsc_start = read_tsc();

    // Wait for 100ms
    while crate::timer::get_ticks() < pit_start + 100 {
        core::hint::spin_loop();
    }

    let tsc_end = read_tsc();
    let tsc_diff = tsc_end - tsc_start;

    // TSC ticks per second = (tsc_diff * 10) since we measured 100ms
    let freq = tsc_diff * 10;
    TSC_FREQUENCY.store(freq, Ordering::SeqCst);

    crate::serial_println!("TSC frequency: {} Hz ({} MHz)", freq, freq / 1_000_000);
}

/// Get time in nanoseconds since boot
pub fn now_ns() -> u64 {
    let freq = TSC_FREQUENCY.load(Ordering::SeqCst);
    if freq == 0 {
        return 0;
    }

    // tsc_ticks / (freq / 1e9) = tsc_ticks * 1e9 / freq
    let tsc = read_tsc();
    (tsc as u128 * 1_000_000_000 / freq as u128) as u64
}

/// High-precision sleep using TSC
pub fn sleep_ns(ns: u64) {
    let freq = TSC_FREQUENCY.load(Ordering::SeqCst);
    if freq == 0 {
        return;
    }

    let tsc_ticks = ns as u128 * freq as u128 / 1_000_000_000;
    let target = read_tsc() + tsc_ticks as u64;

    while read_tsc() < target {
        core::hint::spin_loop();
    }
}
```

---

## Partie 3: Integration with Interrupts

### Exercice 3.1: Complete Interrupt Setup

```rust
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use pic8259::ChainedPics;
use spin;
use lazy_static::lazy_static;

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: spin::Mutex<ChainedPics> =
    spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard = PIC_1_OFFSET + 1,
}

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();

        // CPU exceptions
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(crate::gdt::DOUBLE_FAULT_IST_INDEX);
        }
        idt.page_fault.set_handler_fn(page_fault_handler);

        // Hardware interrupts
        idt[InterruptIndex::Timer as usize].set_handler_fn(timer_interrupt_handler);
        idt[InterruptIndex::Keyboard as usize].set_handler_fn(keyboard_interrupt_handler);

        idt
    };
}

pub fn init_idt() {
    IDT.load();
}

extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    crate::timer::tick();
    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptIndex::Timer as u8);
    }
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    crate::keyboard::handle_keyboard_interrupt();
    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptIndex::Keyboard as u8);
    }
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    crate::println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: x86_64::structures::idt::PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;
    crate::println!("EXCEPTION: PAGE FAULT");
    crate::println!("Accessed Address: {:?}", Cr2::read());
    crate::println!("Error Code: {:?}", error_code);
    crate::println!("{:#?}", stack_frame);
    crate::hlt_loop();
}

/// Initialize interrupts
pub fn init() {
    init_idt();
    unsafe { PICS.lock().initialize() };
    crate::timer::init_pit(1000); // 1000 Hz
    x86_64::instructions::interrupts::enable();
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Keyboard driver implementation | 25 |
| Scancode decoding | 15 |
| Timer setup | 25 |
| Interrupt integration | 20 |
| High-resolution timing | 15 |
| **Total** | **100** |

---

## Ressources

- [pc-keyboard crate docs](https://docs.rs/pc-keyboard/)
- [OSDev Wiki: PS/2 Keyboard](https://wiki.osdev.org/PS/2_Keyboard)
- [OSDev Wiki: PIT](https://wiki.osdev.org/Programmable_Interval_Timer)
- [pic8259 crate docs](https://docs.rs/pic8259/)
