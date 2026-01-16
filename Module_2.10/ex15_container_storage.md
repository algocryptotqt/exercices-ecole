# ex15: Container Storage

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 3h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.28: Container Storage (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Storage drivers | OverlayFS, devicemapper, btrfs |
| b | OverlayFS | Union filesystem |
| c | Lower/Upper | Read-only/read-write |
| d | Volumes | Persistent storage |
| e | Bind mounts | Host directory |
| f | tmpfs | In-memory |
| g | Volume drivers | Plugins |

---

## Sujet

Comprendre le stockage des conteneurs avec volumes et storage drivers.

---

## Exemple

```c
#include "container_storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================
// Storage Drivers
// ============================================

void explain_storage_drivers(void) {
    printf("=== Container Storage Drivers ===\n\n");

    printf("Storage drivers provide layered filesystem:\n");
    printf("  - Implement copy-on-write\n");
    printf("  - Stack image layers\n");
    printf("  - Provide writable container layer\n");

    printf("\nCommon drivers:\n");

    printf("\noverlay2 (recommended):\n");
    printf("  - Uses OverlayFS (Linux kernel)\n");
    printf("  - Best performance and stability\n");
    printf("  - Default on modern Linux\n");
    printf("  - Requires kernel 4.0+\n");

    printf("\ndevicemapper:\n");
    printf("  - Block-level storage\n");
    printf("  - Better for RHEL/CentOS 7\n");
    printf("  - More complex setup\n");

    printf("\nbtrfs:\n");
    printf("  - Native COW filesystem\n");
    printf("  - Subvolumes for layers\n");
    printf("  - Requires btrfs filesystem\n");

    printf("\nzfs:\n");
    printf("  - Datasets for layers\n");
    printf("  - Excellent for large deployments\n");
    printf("  - Requires zfs kernel module\n");

    printf("\nCheck current driver:\n");
    printf("  docker info | grep 'Storage Driver'\n");
}

void explain_overlayfs(void) {
    printf("\n=== OverlayFS (overlay2) ===\n\n");

    printf("OverlayFS merges directories into unified view:\n\n");

    printf("  +------------------------+\n");
    printf("  |   Merged View          | <- What you see\n");
    printf("  +------------------------+\n");
    printf("           |\n");
    printf("  +--------+--------+\n");
    printf("  |                 |\n");
    printf("  v                 v\n");
    printf("  +----------+  +----------+\n");
    printf("  | Upper    |  | Lower    |\n");
    printf("  | (RW)     |  | (RO)     |\n");
    printf("  +----------+  +----------+\n");
    printf("  Container     Image layers\n");
    printf("  layer\n");

    printf("\nDirectory structure:\n");
    printf("  /var/lib/docker/overlay2/<layer-id>/\n");
    printf("  ├── diff/      # Layer content\n");
    printf("  ├── merged/    # Unified view (when mounted)\n");
    printf("  ├── work/      # OverlayFS work directory\n");
    printf("  └── lower      # File pointing to lower layers\n");

    printf("\nCopy-on-Write behavior:\n");
    printf("  - Read: Search upper, then lower layers\n");
    printf("  - Write: Copy file to upper, then modify\n");
    printf("  - Delete: Create 'whiteout' file in upper\n");
    printf("  - Directory: Create 'opaque' marker\n");

    printf("\nMount command (internal):\n");
    printf("  mount -t overlay overlay -o \\\n");
    printf("    lowerdir=layer1:layer2:layer3,\\\n");
    printf("    upperdir=container,\\\n");
    printf("    workdir=work \\\n");
    printf("    /merged\n");
}

// ============================================
// Volumes
// ============================================

void explain_volumes(void) {
    printf("\n=== Docker Volumes ===\n\n");

    printf("Volumes are the preferred way to persist data:\n");
    printf("  - Managed by Docker\n");
    printf("  - Independent of container lifecycle\n");
    printf("  - Can be shared between containers\n");
    printf("  - Support volume drivers for remote storage\n");

    printf("\nVolume operations:\n");
    printf("  # Create volume\n");
    printf("  docker volume create mydata\n");
    printf("\n");
    printf("  # List volumes\n");
    printf("  docker volume ls\n");
    printf("\n");
    printf("  # Inspect volume\n");
    printf("  docker volume inspect mydata\n");
    printf("\n");
    printf("  # Remove volume\n");
    printf("  docker volume rm mydata\n");
    printf("\n");
    printf("  # Remove unused volumes\n");
    printf("  docker volume prune\n");

    printf("\nUsing volumes:\n");
    printf("  # Named volume\n");
    printf("  docker run -v mydata:/app/data nginx\n");
    printf("\n");
    printf("  # Anonymous volume\n");
    printf("  docker run -v /app/data nginx\n");
    printf("\n");
    printf("  # Read-only volume\n");
    printf("  docker run -v mydata:/app/data:ro nginx\n");

    printf("\nVolume location:\n");
    printf("  /var/lib/docker/volumes/<volume-name>/_data/\n");
}

void explain_bind_mounts(void) {
    printf("\n=== Bind Mounts ===\n\n");

    printf("Mount host directory into container:\n");
    printf("  - Direct access to host filesystem\n");
    printf("  - Changes immediately visible\n");
    printf("  - Path must exist on host\n");

    printf("\nUsing bind mounts:\n");
    printf("  # Bind mount (absolute path)\n");
    printf("  docker run -v /host/path:/container/path nginx\n");
    printf("\n");
    printf("  # Using --mount (clearer syntax)\n");
    printf("  docker run --mount type=bind,source=/host/path,target=/container/path nginx\n");
    printf("\n");
    printf("  # Read-only\n");
    printf("  docker run -v /host/path:/container/path:ro nginx\n");

    printf("\nCommon use cases:\n");
    printf("  - Development: Mount source code\n");
    printf("  - Config files: Mount /etc/nginx/nginx.conf\n");
    printf("  - Logs: Mount log directory\n");

    printf("\nCaution:\n");
    printf("  - Container can modify host files!\n");
    printf("  - Permission issues (UID mismatch)\n");
    printf("  - Security risk if mounting sensitive paths\n");
}

void explain_tmpfs(void) {
    printf("\n=== tmpfs Mounts ===\n\n");

    printf("In-memory filesystem:\n");
    printf("  - Stored in host memory only\n");
    printf("  - Never written to disk\n");
    printf("  - Lost when container stops\n");
    printf("  - Fast for temporary data\n");

    printf("\nUsage:\n");
    printf("  docker run --tmpfs /tmp nginx\n");
    printf("\n");
    printf("  docker run --mount type=tmpfs,destination=/tmp,tmpfs-size=100m nginx\n");

    printf("\nUse cases:\n");
    printf("  - Sensitive data (secrets)\n");
    printf("  - Temporary files\n");
    printf("  - Build artifacts\n");
    printf("  - Session data\n");
}

// ============================================
// Volume Comparison
// ============================================

void compare_storage_types(void) {
    printf("\n=== Storage Type Comparison ===\n\n");

    printf("+-------------+----------+------------+-----------+\n");
    printf("| Type        | Persist  | Host Access| Use Case  |\n");
    printf("+-------------+----------+------------+-----------+\n");
    printf("| Volume      | Yes      | Docker     | Prod data |\n");
    printf("| Bind mount  | Yes      | Direct     | Dev/config|\n");
    printf("| tmpfs       | No       | Memory     | Temp/secret|\n");
    printf("| Container   | No*      | None       | Test      |\n");
    printf("+-------------+----------+------------+-----------+\n");
    printf("* Container layer lost when container removed\n");
}

// ============================================
// Volume Drivers
// ============================================

void explain_volume_drivers(void) {
    printf("\n=== Volume Drivers ===\n\n");

    printf("Plugins for remote/network storage:\n");

    printf("\nLocal driver (default):\n");
    printf("  docker volume create --driver local \\\n");
    printf("    --opt type=nfs \\\n");
    printf("    --opt o=addr=192.168.1.100,rw \\\n");
    printf("    --opt device=:/path/to/share \\\n");
    printf("    nfs_volume\n");

    printf("\nPopular plugins:\n");
    printf("  - REX-Ray: Multi-platform (AWS, Azure, etc.)\n");
    printf("  - Portworx: Enterprise storage\n");
    printf("  - NetApp: NFS/iSCSI\n");
    printf("  - Flocker: Container data management\n");
    printf("  - GlusterFS: Distributed storage\n");

    printf("\nInstall plugin:\n");
    printf("  docker plugin install rexray/ebs\n");
    printf("  docker volume create --driver rexray/ebs myebs\n");
}

// ============================================
// Best Practices
// ============================================

void show_best_practices(void) {
    printf("\n=== Storage Best Practices ===\n\n");

    printf("1. Don't store data in container layer\n");
    printf("   - Container layer is ephemeral\n");
    printf("   - Performance overhead for writes\n");

    printf("\n2. Use volumes for persistent data\n");
    printf("   docker run -v dbdata:/var/lib/mysql mysql\n");

    printf("\n3. Use bind mounts for development\n");
    printf("   docker run -v $(pwd):/app node npm start\n");

    printf("\n4. Use tmpfs for secrets\n");
    printf("   docker run --tmpfs /run/secrets myapp\n");

    printf("\n5. Consider storage driver for workload\n");
    printf("   - overlay2: General purpose\n");
    printf("   - devicemapper: RHEL/block storage\n");
    printf("   - zfs: Large scale, advanced features\n");

    printf("\n6. Back up your volumes!\n");
    printf("   docker run --rm -v mydata:/data -v $(pwd):/backup \\\n");
    printf("     alpine tar cvf /backup/backup.tar /data\n");

    printf("\n7. Use named volumes, not anonymous\n");
    printf("   Bad:  docker run -v /data mysql\n");
    printf("   Good: docker run -v mysql_data:/data mysql\n");
}

int main(void) {
    explain_storage_drivers();
    explain_overlayfs();
    explain_volumes();
    explain_bind_mounts();
    explain_tmpfs();
    compare_storage_types();
    explain_volume_drivers();
    show_best_practices();

    return 0;
}
```

---

## Fichiers

```
ex15/
├── container_storage.h
├── storage_drivers.c
├── overlayfs.c
├── volumes.c
├── bind_mounts.c
└── Makefile
```
