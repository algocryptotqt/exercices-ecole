# ex18: Storage Subsystem & LVM

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.33: Storage Subsystem (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Block devices | Fixed-size blocks |
| b | Character devices | Byte stream |
| c | Block layer | Linux kernel |
| d | Request queue | I/O scheduling |
| e | Bio | Block I/O |
| f | I/O schedulers | mq-deadline, BFQ, none |
| g | Multi-queue | Modern SSD support |

### 2.10.34: Storage Technologies (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | SATA | Serial ATA |
| b | SAS | Serial Attached SCSI |
| c | NVMe | Non-Volatile Memory Express |
| d | NVMe advantages | Low latency, parallel |
| e | NVMe queues | Multiple submission/completion |
| f | HDD vs SSD | Mechanical vs flash |
| g | RAID | Redundancy |

### 2.10.35: LVM (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | LVM | Logical Volume Manager |
| b | Physical Volume | PV, actual disk |
| c | Volume Group | VG, pool of PVs |
| d | Logical Volume | LV, virtual partition |
| e | pvcreate | Create PV |
| f | vgcreate | Create VG |
| g | lvcreate | Create LV |
| h | Resize | Grow/shrink |
| i | Snapshots | Point-in-time copy |

---

## Sujet

Comprendre le sous-systeme de stockage Linux et LVM.

---

## Exemple

```c
#include "storage.h"
#include <stdio.h>
#include <stdlib.h>

// ============================================
// Block Layer
// ============================================

void explain_block_layer(void) {
    printf("=== Linux Block Layer ===\n\n");

    printf("Block vs Character Devices:\n");
    printf("  Block:     Fixed-size units (512B, 4KB)\n");
    printf("             Random access, buffered\n");
    printf("             Example: /dev/sda, /dev/nvme0n1\n");
    printf("\n");
    printf("  Character: Byte stream\n");
    printf("             Sequential access, unbuffered\n");
    printf("             Example: /dev/tty, /dev/null\n");

    printf("\nBlock Layer Stack:\n");
    printf("  +------------------------+\n");
    printf("  | Filesystem (ext4, xfs) |\n");
    printf("  +------------------------+\n");
    printf("  | Page Cache             |\n");
    printf("  +------------------------+\n");
    printf("  | Block Layer            |\n");
    printf("  +------------------------+\n");
    printf("  | I/O Scheduler          |\n");
    printf("  +------------------------+\n");
    printf("  | Device Driver          |\n");
    printf("  +------------------------+\n");
    printf("  | Hardware               |\n");
    printf("  +------------------------+\n");

    printf("\nBIO (Block I/O):\n");
    printf("  - Unit of I/O in kernel\n");
    printf("  - Contains: device, sector, segments\n");
    printf("  - Merged and sorted by scheduler\n");
}

void explain_io_schedulers(void) {
    printf("\n=== I/O Schedulers ===\n\n");

    printf("Multi-Queue Block Layer (blk-mq):\n");
    printf("  Modern architecture for SSDs/NVMe\n");
    printf("  Multiple hardware queues\n");
    printf("  Per-CPU software queues\n");

    printf("\nAvailable schedulers:\n");

    printf("\nnone:\n");
    printf("  - No scheduling (FIFO)\n");
    printf("  - Best for NVMe/SSD with internal scheduling\n");
    printf("  - Lowest CPU overhead\n");

    printf("\nmq-deadline:\n");
    printf("  - Deadline-based scheduling\n");
    printf("  - Good for mixed workloads\n");
    printf("  - Ensures requests don't starve\n");

    printf("\nbfq (Budget Fair Queueing):\n");
    printf("  - Fair I/O distribution\n");
    printf("  - Good for interactive workloads\n");
    printf("  - Higher CPU overhead\n");

    printf("\nkyber:\n");
    printf("  - Simple, efficient\n");
    printf("  - Targets fast devices\n");
    printf("  - Limited tuning options\n");

    printf("\nCheck/set scheduler:\n");
    printf("  cat /sys/block/sda/queue/scheduler\n");
    printf("  echo mq-deadline > /sys/block/sda/queue/scheduler\n");
}

// ============================================
// Storage Technologies
// ============================================

void explain_storage_tech(void) {
    printf("\n=== Storage Technologies ===\n\n");

    printf("SATA (Serial ATA):\n");
    printf("  - Consumer/mainstream\n");
    printf("  - Up to 6 Gbps (SATA III)\n");
    printf("  - Single queue, 32 commands\n");
    printf("  - HDD or SSD\n");

    printf("\nSAS (Serial Attached SCSI):\n");
    printf("  - Enterprise\n");
    printf("  - Up to 24 Gbps (SAS-4)\n");
    printf("  - Dual-port for redundancy\n");
    printf("  - Better error handling\n");

    printf("\nNVMe (Non-Volatile Memory Express):\n");
    printf("  - Designed for flash\n");
    printf("  - Direct PCIe connection\n");
    printf("  - Up to 64K queues, 64K commands each\n");
    printf("  - Microsecond latency\n");
    printf("  - Parallel I/O (multiple cores)\n");

    printf("\nHDD vs SSD:\n");
    printf("  +-----------+----------+----------+\n");
    printf("  |           |   HDD    |   SSD    |\n");
    printf("  +-----------+----------+----------+\n");
    printf("  | Latency   | 5-10 ms  | 0.1 ms   |\n");
    printf("  | IOPS      | 100-200  | 100,000+ |\n");
    printf("  | Seq. Read | 200 MB/s | 3+ GB/s  |\n");
    printf("  | Power     | 5-10 W   | 2-5 W    |\n");
    printf("  | Durability| Years    | TBW limit|\n");
    printf("  +-----------+----------+----------+\n");
}

void explain_raid(void) {
    printf("\n=== RAID ===\n\n");

    printf("RAID Levels:\n");

    printf("\nRAID 0 (Striping):\n");
    printf("  - Performance: 2x (n disks)\n");
    printf("  - Capacity: 100%%\n");
    printf("  - Redundancy: None!\n");
    printf("  - Minimum: 2 disks\n");

    printf("\nRAID 1 (Mirroring):\n");
    printf("  - Performance: 1x write, 2x read\n");
    printf("  - Capacity: 50%%\n");
    printf("  - Redundancy: 1 disk failure\n");
    printf("  - Minimum: 2 disks\n");

    printf("\nRAID 5 (Striping + Parity):\n");
    printf("  - Performance: (n-1)x\n");
    printf("  - Capacity: (n-1)/n\n");
    printf("  - Redundancy: 1 disk failure\n");
    printf("  - Minimum: 3 disks\n");

    printf("\nRAID 6 (Double Parity):\n");
    printf("  - Performance: (n-2)x\n");
    printf("  - Capacity: (n-2)/n\n");
    printf("  - Redundancy: 2 disk failures\n");
    printf("  - Minimum: 4 disks\n");

    printf("\nRAID 10 (1+0):\n");
    printf("  - Mirror then stripe\n");
    printf("  - Best performance + redundancy\n");
    printf("  - Capacity: 50%%\n");
    printf("  - Minimum: 4 disks\n");

    printf("\nLinux software RAID (mdadm):\n");
    printf("  mdadm --create /dev/md0 --level=1 \\\n");
    printf("        --raid-devices=2 /dev/sdb /dev/sdc\n");
}

// ============================================
// LVM
// ============================================

void explain_lvm(void) {
    printf("\n=== LVM (Logical Volume Manager) ===\n\n");

    printf("LVM Hierarchy:\n");
    printf("  +-------------------+\n");
    printf("  | Logical Volume    |  (like partition)\n");
    printf("  +-------------------+\n");
    printf("           |\n");
    printf("  +-------------------+\n");
    printf("  | Volume Group      |  (pool of space)\n");
    printf("  +-------------------+\n");
    printf("           |\n");
    printf("  +-------------------+\n");
    printf("  | Physical Volume   |  (disk/partition)\n");
    printf("  +-------------------+\n");

    printf("\nAdvantages:\n");
    printf("  - Resize volumes online\n");
    printf("  - Add storage dynamically\n");
    printf("  - Snapshots\n");
    printf("  - Thin provisioning\n");
    printf("  - RAID integration\n");
}

void show_lvm_commands(void) {
    printf("\n=== LVM Commands ===\n\n");

    printf("Physical Volumes (PV):\n");
    printf("  pvcreate /dev/sdb         # Initialize disk\n");
    printf("  pvs                        # List PVs\n");
    printf("  pvdisplay /dev/sdb         # Details\n");
    printf("  pvremove /dev/sdb          # Remove PV\n");

    printf("\nVolume Groups (VG):\n");
    printf("  vgcreate myvg /dev/sdb /dev/sdc  # Create VG\n");
    printf("  vgs                              # List VGs\n");
    printf("  vgdisplay myvg                   # Details\n");
    printf("  vgextend myvg /dev/sdd           # Add PV\n");
    printf("  vgreduce myvg /dev/sdd           # Remove PV\n");

    printf("\nLogical Volumes (LV):\n");
    printf("  lvcreate -L 10G -n data myvg     # Create 10GB LV\n");
    printf("  lvcreate -l 100%%FREE -n data myvg # Use all space\n");
    printf("  lvs                              # List LVs\n");
    printf("  lvdisplay /dev/myvg/data         # Details\n");
    printf("  lvremove /dev/myvg/data          # Remove LV\n");

    printf("\nUsing LV:\n");
    printf("  mkfs.ext4 /dev/myvg/data\n");
    printf("  mount /dev/myvg/data /mnt\n");
}

void show_lvm_resize(void) {
    printf("\n=== LVM Resize Operations ===\n\n");

    printf("Extend LV:\n");
    printf("  # Add 5GB\n");
    printf("  lvextend -L +5G /dev/myvg/data\n");
    printf("  \n");
    printf("  # Or extend to fill VG\n");
    printf("  lvextend -l +100%%FREE /dev/myvg/data\n");
    printf("  \n");
    printf("  # Resize filesystem\n");
    printf("  resize2fs /dev/myvg/data    # ext4\n");
    printf("  xfs_growfs /mnt              # xfs (mounted)\n");

    printf("\nShrink LV (ext4 only):\n");
    printf("  # Unmount first!\n");
    printf("  umount /mnt\n");
    printf("  \n");
    printf("  # Check filesystem\n");
    printf("  e2fsck -f /dev/myvg/data\n");
    printf("  \n");
    printf("  # Shrink filesystem first\n");
    printf("  resize2fs /dev/myvg/data 5G\n");
    printf("  \n");
    printf("  # Then shrink LV\n");
    printf("  lvreduce -L 5G /dev/myvg/data\n");

    printf("\nOne command (extend + resize):\n");
    printf("  lvextend -r -L +5G /dev/myvg/data\n");
}

void show_lvm_snapshots(void) {
    printf("\n=== LVM Snapshots ===\n\n");

    printf("Create snapshot:\n");
    printf("  lvcreate -L 1G -s -n snap1 /dev/myvg/data\n");
    printf("  \n");
    printf("  -s: snapshot\n");
    printf("  -L 1G: space for changes (COW)\n");

    printf("\nMount snapshot:\n");
    printf("  mount -o ro /dev/myvg/snap1 /mnt/snapshot\n");

    printf("\nRestore from snapshot:\n");
    printf("  umount /mnt\n");
    printf("  lvconvert --merge /dev/myvg/snap1\n");
    printf("  # Reboot or reactivate LV\n");

    printf("\nRemove snapshot:\n");
    printf("  lvremove /dev/myvg/snap1\n");

    printf("\nThin Provisioning:\n");
    printf("  # Create thin pool\n");
    printf("  lvcreate -L 100G --thinpool pool myvg\n");
    printf("  \n");
    printf("  # Create thin LV (can overprovision)\n");
    printf("  lvcreate -V 50G --thin -n thin1 myvg/pool\n");
    printf("  \n");
    printf("  # Thin snapshots are instant and small\n");
    printf("  lvcreate -s --name snap1 myvg/thin1\n");
}

int main(void) {
    explain_block_layer();
    explain_io_schedulers();
    explain_storage_tech();
    explain_raid();
    explain_lvm();
    show_lvm_commands();
    show_lvm_resize();
    show_lvm_snapshots();

    return 0;
}
```

---

## Fichiers

```
ex18/
├── storage.h
├── block_layer.c
├── io_schedulers.c
├── storage_tech.c
├── lvm.c
└── Makefile
```
