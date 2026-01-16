# [Module 2.7] - Exercise 13: Linux Kernel Modules in Rust

## Metadonnees

```yaml
module: "2.7 - Kernel Development"
exercise: "ex13"
title: "Linux Kernel Modules & Drivers in Rust"
difficulty: expert
estimated_time: "6 heures"
prerequisite_exercises: ["ex00", "ex01", "ex10"]
concepts_requis: ["kernel modules", "device drivers", "Rust no_std"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.7.21: Linux Kernel Module in Rust (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.7.21.a | Module structure | `kernel::module!` macro |
| 2.7.21.b | `init` function | Module initialization |
| 2.7.21.c | `drop` | Module cleanup RAII |
| 2.7.21.d | `ThisModule` | Module reference handle |
| 2.7.21.e | Error handling | `kernel::error::Result` |
| 2.7.21.f | `pr_info!`, `pr_err!` | Kernel logging macros |
| 2.7.21.g | `kernel::sync::Mutex` | Kernel mutex primitives |
| 2.7.21.h | `kernel::file::File` | File operations trait |
| 2.7.21.i | `kernel::miscdev` | Misc device registration |
| 2.7.21.j | Building | `make LLVM=1` compilation |

### 2.7.22: Writing a Linux Rust Driver (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.7.22.a | Character device | `kernel::file` char device |
| 2.7.22.b | `FileOperations` trait | Driver callback implementations |
| 2.7.22.c | `open` | Device open callback |
| 2.7.22.d | `read` | Data read from device |
| 2.7.22.e | `write` | Data write to device |
| 2.7.22.f | `ioctl` | Control commands |
| 2.7.22.g | `kernel::miscdev::MiscDevice` | Misc driver pattern |
| 2.7.22.h | Registration | Automatic RAII registration |
| 2.7.22.i | User-kernel copy | `UserSlice` safe copies |
| 2.7.22.j | Error codes | `kernel::error::code` constants |

---

## Partie 1: Kernel Module Structure (2.7.21)

### Exercice 1.1: Basic Module Structure

```rust
// samples/rust/rust_module_basic.rs
//! Basic Rust kernel module demonstrating structure

use kernel::prelude::*;

module! {
    type: BasicModule,
    name: "rust_basic",
    author: "ODYSSEY Student",
    description: "Basic Rust kernel module",
    license: "GPL",
}

struct BasicModule {
    // Module state
    counter: u32,
}

impl kernel::Module for BasicModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust basic module initialized!\n");

        Ok(BasicModule { counter: 0 })
    }
}

impl Drop for BasicModule {
    fn drop(&mut self) {
        pr_info!("Rust basic module cleanup, counter was: {}\n", self.counter);
    }
}
```

**Questions:**
1. Que fait la macro `module!` et quels champs sont obligatoires ?
2. Expliquez le rôle de `ThisModule` dans `init` ?
3. Pourquoi `Drop` est important pour les modules kernel ?

### Exercice 1.2: Module avec Mutex Kernel

```rust
// samples/rust/rust_mutex_module.rs
//! Module demonstrating kernel mutex usage

use kernel::prelude::*;
use kernel::sync::Mutex;

module! {
    type: MutexModule,
    name: "rust_mutex",
    author: "ODYSSEY Student",
    description: "Mutex demonstration module",
    license: "GPL",
}

struct MutexModule {
    data: Mutex<SharedData>,
}

struct SharedData {
    value: i64,
    access_count: u64,
}

impl kernel::Module for MutexModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Mutex module loading...\n");

        let data = kernel::new_mutex!(SharedData {
            value: 0,
            access_count: 0,
        });

        // Test mutex access
        {
            let mut guard = data.lock();
            guard.value = 42;
            guard.access_count += 1;
            pr_info!("Initial value set to: {}\n", guard.value);
        }

        Ok(MutexModule { data })
    }
}

impl Drop for MutexModule {
    fn drop(&mut self) {
        let guard = self.data.lock();
        pr_info!("Module unloading, total accesses: {}\n", guard.access_count);
    }
}
```

**Questions:**
1. Quelle différence entre `kernel::sync::Mutex` et `std::sync::Mutex` ?
2. Pourquoi utilise-t-on `new_mutex!` au lieu de `Mutex::new()` ?
3. Que se passe-t-il si le mutex est locked pendant le drop ?

### Exercice 1.3: Error Handling Kernel

```rust
// samples/rust/rust_error_module.rs
//! Demonstrating kernel error handling in Rust

use kernel::prelude::*;
use kernel::error::code;

module! {
    type: ErrorModule,
    name: "rust_error",
    author: "ODYSSEY Student",
    description: "Error handling demonstration",
    license: "GPL",
}

struct ErrorModule;

fn fallible_operation(should_fail: bool) -> Result<i32> {
    if should_fail {
        pr_err!("Operation failed!\n");
        return Err(code::EINVAL);
    }
    Ok(42)
}

fn chain_operations() -> Result<i32> {
    let a = fallible_operation(false)?;
    let b = fallible_operation(false)?;
    Ok(a + b)
}

impl kernel::Module for ErrorModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Testing error handling...\n");

        // Test successful operation
        match fallible_operation(false) {
            Ok(val) => pr_info!("Success: {}\n", val),
            Err(e) => pr_err!("Error: {:?}\n", e),
        }

        // Test error propagation
        let result = chain_operations();
        pr_info!("Chain result: {:?}\n", result);

        // Return error to prevent loading (for testing)
        // return Err(code::ENODEV);

        Ok(ErrorModule)
    }
}
```

**Questions:**
1. Listez 5 codes d'erreur kernel courants et leurs significations ?
2. Comment `?` operator fonctionne avec `kernel::error::Result` ?
3. Que se passe-t-il si `init` retourne une erreur ?

---

## Partie 2: Character Device Driver (2.7.22)

### Exercice 2.1: Misc Device Basic

```rust
// samples/rust/rust_misc_dev.rs
//! Simple misc device driver in Rust

use kernel::prelude::*;
use kernel::miscdev;
use kernel::file::{self, File, Operations};
use kernel::io_buffer::{IoBufferReader, IoBufferWriter};

module! {
    type: MiscDevModule,
    name: "rust_misc",
    author: "ODYSSEY Student",
    description: "Misc device in Rust",
    license: "GPL",
}

struct MiscDevModule {
    _dev: Pin<Box<miscdev::Registration<RustMiscDev>>>,
}

#[pin_data]
struct RustMiscDev;

#[vtable]
impl Operations for RustMiscDev {
    type Data = ();
    type OpenData = ();

    fn open(_context: &(), _file: &File) -> Result<Self::Data> {
        pr_info!("rust_misc: device opened\n");
        Ok(())
    }

    fn read(
        _data: (),
        _file: &File,
        writer: &mut impl IoBufferWriter,
        _offset: u64,
    ) -> Result<usize> {
        let message = b"Hello from Rust kernel driver!\n";
        writer.write_slice(message)?;
        Ok(message.len())
    }

    fn write(
        _data: (),
        _file: &File,
        reader: &mut impl IoBufferReader,
        _offset: u64,
    ) -> Result<usize> {
        let len = reader.len();
        let mut buf = vec![0u8; len];
        reader.read_slice(&mut buf)?;
        pr_info!("rust_misc: received {} bytes\n", len);
        Ok(len)
    }
}

impl kernel::Module for MiscDevModule {
    fn init(module: &'static ThisModule) -> Result<Self> {
        pr_info!("Registering misc device...\n");

        let dev = miscdev::Registration::new_pinned(
            fmt!("rust_misc"),
            (),
            module,
        )?;

        Ok(MiscDevModule { _dev: dev })
    }
}
```

**Questions:**
1. Quelle est la différence entre misc device et character device ?
2. Expliquez le trait `Operations` et ses méthodes obligatoires ?
3. Que fait `Pin<Box<...>>` pour le device registration ?

### Exercice 2.2: Device avec IOCTL

```rust
// samples/rust/rust_ioctl_dev.rs
//! Device driver with ioctl support

use kernel::prelude::*;
use kernel::miscdev;
use kernel::file::{self, File, Operations};
use kernel::ioctl;
use kernel::user_ptr::UserSlicePtr;

module! {
    type: IoctlDevModule,
    name: "rust_ioctl",
    author: "ODYSSEY Student",
    description: "IOCTL device in Rust",
    license: "GPL",
}

// IOCTL command definitions
const RUST_IOCTL_MAGIC: u32 = b'R' as u32;
const RUST_IOCTL_GET_VALUE: u32 = ioctl::_IOR::<i32>(RUST_IOCTL_MAGIC, 1);
const RUST_IOCTL_SET_VALUE: u32 = ioctl::_IOW::<i32>(RUST_IOCTL_MAGIC, 2);
const RUST_IOCTL_RESET: u32 = ioctl::_IO(RUST_IOCTL_MAGIC, 3);

struct IoctlDevModule {
    _dev: Pin<Box<miscdev::Registration<RustIoctlDev>>>,
}

struct DeviceState {
    value: i32,
}

#[pin_data]
struct RustIoctlDev {
    state: Mutex<DeviceState>,
}

#[vtable]
impl Operations for RustIoctlDev {
    type Data = Arc<RustIoctlDev>;
    type OpenData = Arc<RustIoctlDev>;

    fn open(context: &Arc<RustIoctlDev>, _file: &File) -> Result<Self::Data> {
        pr_info!("rust_ioctl: device opened\n");
        Ok(context.clone())
    }

    fn ioctl(
        data: Arc<RustIoctlDev>,
        _file: &File,
        cmd: u32,
        arg: usize,
    ) -> Result<i32> {
        match cmd {
            RUST_IOCTL_GET_VALUE => {
                let guard = data.state.lock();
                let ptr = UserSlicePtr::new(arg as *mut _, core::mem::size_of::<i32>());
                ptr.writer().write(&guard.value)?;
                Ok(0)
            }
            RUST_IOCTL_SET_VALUE => {
                let ptr = UserSlicePtr::new(arg as *const _, core::mem::size_of::<i32>());
                let mut value: i32 = 0;
                ptr.reader().read(&mut value)?;
                let mut guard = data.state.lock();
                guard.value = value;
                pr_info!("Value set to: {}\n", value);
                Ok(0)
            }
            RUST_IOCTL_RESET => {
                let mut guard = data.state.lock();
                guard.value = 0;
                pr_info!("Value reset\n");
                Ok(0)
            }
            _ => Err(kernel::error::code::ENOTTY),
        }
    }
}

impl kernel::Module for IoctlDevModule {
    fn init(module: &'static ThisModule) -> Result<Self> {
        let dev_state = Arc::try_new(RustIoctlDev {
            state: Mutex::new(DeviceState { value: 0 }),
        })?;

        let dev = miscdev::Registration::new_pinned(
            fmt!("rust_ioctl"),
            dev_state,
            module,
        )?;

        Ok(IoctlDevModule { _dev: dev })
    }
}
```

**Questions:**
1. Expliquez les macros `_IOR`, `_IOW`, `_IO` pour IOCTL ?
2. Comment `UserSlicePtr` garantit la sécurité des copies user-kernel ?
3. Pourquoi retourne-t-on `ENOTTY` pour les commandes inconnues ?

### Exercice 2.3: Exercice Pratique - Counter Device

Implémentez un device driver `/dev/rust_counter` qui:

```rust
// TODO: Implement counter device
// Requirements:
// 1. read() returns current counter value as string
// 2. write() increments counter by written value
// 3. IOCTL_RESET resets to 0
// 4. IOCTL_GET returns current value
// 5. IOCTL_SET sets specific value
// 6. Thread-safe with kernel mutex
```

**Fichiers à créer:**
- `rust_counter.rs` - Le module kernel
- `test_counter.c` - Programme userspace de test

---

## Partie 3: Building & Testing Kernel Modules

### Exercice 3.1: Makefile et Build System

```makefile
# Kbuild file for Rust kernel module
obj-m := rust_basic.o rust_misc.o rust_ioctl.o

# Building outside kernel tree
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) LLVM=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Load module
load:
	sudo insmod rust_basic.ko

unload:
	sudo rmmod rust_basic

# View kernel log
dmesg:
	sudo dmesg | tail -20
```

**Commandes importantes:**

```bash
# Vérifier support Rust dans kernel
grep CONFIG_RUST /boot/config-$(uname -r)

# Build avec LLVM
make LLVM=1 LLVM_IAS=1

# Charger le module
sudo insmod rust_basic.ko

# Vérifier le module
lsmod | grep rust

# Voir les logs
sudo dmesg | tail

# Décharger
sudo rmmod rust_basic

# Info sur le module
modinfo rust_basic.ko
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Module structure comprehension | 20 |
| init/drop lifecycle | 15 |
| Error handling | 15 |
| Character device implementation | 20 |
| IOCTL handling | 15 |
| Build system mastery | 15 |
| **Total** | **100** |

---

## Ressources

- [Rust for Linux Documentation](https://rust-for-linux.com/)
- [Linux Kernel Rust API](https://rust-for-linux.github.io/docs/)
- [LWN: Rust in the Kernel](https://lwn.net/Articles/908347/)
- [Kernel Module Programming Guide](https://sysprog21.github.io/lkmpg/)
