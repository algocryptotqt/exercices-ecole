# ex14: Container Networking

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.27: Container Networking (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Bridge network | Default mode |
| b | docker0 | Default bridge |
| c | Host network | Share host stack |
| d | None network | No networking |
| e | Overlay network | Multi-host |
| f | Macvlan | Direct to physical |
| g | Port mapping | -p host:container |

---

## Sujet

Maitriser les differents modes de networking pour les conteneurs.

---

## Exemple

```c
#include "container_networking.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void explain_networking_modes(void) {
    printf("=== Container Networking Modes ===\n\n");

    printf("Docker supports multiple networking modes:\n");
    printf("  - bridge (default)\n");
    printf("  - host\n");
    printf("  - none\n");
    printf("  - overlay\n");
    printf("  - macvlan\n");
    printf("  - ipvlan\n");
}

// ============================================
// Bridge Network (Default)
// ============================================

void explain_bridge_network(void) {
    printf("\n=== Bridge Network ===\n\n");

    printf("Default networking mode\n");
    printf("  - Each container gets own IP\n");
    printf("  - Containers can communicate via bridge\n");
    printf("  - NAT for external communication\n");

    printf("\nNetwork topology:\n\n");
    printf("  Internet\n");
    printf("      |\n");
    printf("      | NAT\n");
    printf("  +---+---+  Host (eth0: 192.168.1.100)\n");
    printf("  |       |\n");
    printf("  | docker0 (172.17.0.1)\n");
    printf("  |   |\n");
    printf("  +---+---+---+---+\n");
    printf("      |       |\n");
    printf("   veth0    veth1\n");
    printf("      |       |\n");
    printf("  +---+---+ +---+---+\n");
    printf("  |  C1   | |  C2   |\n");
    printf("  |.17.0.2| |.17.0.3|\n");
    printf("  +-------+ +-------+\n");

    printf("\nCommands:\n");
    printf("  # List networks\n");
    printf("  docker network ls\n");
    printf("\n");
    printf("  # Inspect default bridge\n");
    printf("  docker network inspect bridge\n");
    printf("\n");
    printf("  # Create custom bridge\n");
    printf("  docker network create --driver bridge mynet\n");
    printf("\n");
    printf("  # Run container on custom network\n");
    printf("  docker run --network mynet --name web nginx\n");
    printf("\n");
    printf("  # Connect running container to network\n");
    printf("  docker network connect mynet mycontainer\n");
}

void explain_port_mapping(void) {
    printf("\n=== Port Mapping ===\n\n");

    printf("Map host port to container port:\n");
    printf("  docker run -p <host_port>:<container_port> image\n");

    printf("\nExamples:\n");
    printf("  # Map port 80 on host to 80 in container\n");
    printf("  docker run -p 80:80 nginx\n");
    printf("\n");
    printf("  # Map to different port\n");
    printf("  docker run -p 8080:80 nginx\n");
    printf("\n");
    printf("  # Bind to specific interface\n");
    printf("  docker run -p 127.0.0.1:8080:80 nginx\n");
    printf("\n");
    printf("  # Random host port\n");
    printf("  docker run -p 80 nginx\n");
    printf("  docker port <container>  # See assigned port\n");
    printf("\n");
    printf("  # UDP port\n");
    printf("  docker run -p 53:53/udp bind\n");
    printf("\n");
    printf("  # Publish all exposed ports\n");
    printf("  docker run -P nginx\n");

    printf("\nHow it works (iptables):\n");
    printf("  # Docker creates DNAT rules:\n");
    printf("  iptables -t nat -A DOCKER -p tcp --dport 8080 \\\n");
    printf("           -j DNAT --to-destination 172.17.0.2:80\n");
}

// ============================================
// Host Network
// ============================================

void explain_host_network(void) {
    printf("\n=== Host Network ===\n\n");

    printf("Container shares host's network stack:\n");
    printf("  - No network isolation\n");
    printf("  - Best performance (no NAT overhead)\n");
    printf("  - Container uses host's IP\n");
    printf("  - Port conflicts with host services\n");

    printf("\nUsage:\n");
    printf("  docker run --network host nginx\n");
    printf("  # nginx now listens on host's port 80\n");

    printf("\nUse cases:\n");
    printf("  - Performance-critical applications\n");
    printf("  - Applications that need to see all network traffic\n");
    printf("  - When NAT causes issues\n");

    printf("\nCaution:\n");
    printf("  - Less secure (no network isolation)\n");
    printf("  - Not portable (depends on host config)\n");
}

// ============================================
// None Network
// ============================================

void explain_none_network(void) {
    printf("\n=== None Network ===\n\n");

    printf("No networking (only loopback):\n");
    printf("  docker run --network none alpine\n");

    printf("\nUse cases:\n");
    printf("  - Batch processing jobs\n");
    printf("  - Security-sensitive workloads\n");
    printf("  - Testing without network\n");

    printf("\nContainer has only:\n");
    printf("  - lo interface (127.0.0.1)\n");
    printf("  - No external connectivity\n");
}

// ============================================
// Overlay Network
// ============================================

void explain_overlay_network(void) {
    printf("\n=== Overlay Network ===\n\n");

    printf("Multi-host networking for swarm/orchestration:\n");
    printf("  - Spans multiple Docker hosts\n");
    printf("  - Uses VXLAN encapsulation\n");
    printf("  - Requires swarm mode or external KV store\n");

    printf("\nTopology:\n\n");
    printf("  Host A                    Host B\n");
    printf("  +--------+                +--------+\n");
    printf("  |  C1    |                |  C2    |\n");
    printf("  |10.0.0.2|                |10.0.0.3|\n");
    printf("  +---+----+                +---+----+\n");
    printf("      |                         |\n");
    printf("  +---+---------Overlay---------+---+\n");
    printf("      |                         |\n");
    printf("      | VXLAN tunnel            |\n");
    printf("      |                         |\n");
    printf("  +---+----+                +---+----+\n");
    printf("  |eth0    |================|eth0    |\n");
    printf("  |Host A  |   Physical     |Host B  |\n");
    printf("  +--------+   Network      +--------+\n");

    printf("\nSetup:\n");
    printf("  # Initialize swarm\n");
    printf("  docker swarm init\n");
    printf("\n");
    printf("  # Create overlay network\n");
    printf("  docker network create --driver overlay myoverlay\n");
    printf("\n");
    printf("  # Deploy service\n");
    printf("  docker service create --network myoverlay nginx\n");
}

// ============================================
// Macvlan
// ============================================

void explain_macvlan(void) {
    printf("\n=== Macvlan Network ===\n\n");

    printf("Assign MAC address to container:\n");
    printf("  - Container appears as physical device on network\n");
    printf("  - Gets IP from physical network's DHCP\n");
    printf("  - Best for legacy applications\n");
    printf("  - No NAT, no port mapping needed\n");

    printf("\nModes:\n");
    printf("  - bridge: Default, containers can communicate\n");
    printf("  - vepa: Traffic through external switch\n");
    printf("  - private: No inter-container traffic\n");
    printf("  - passthrough: One container per parent interface\n");

    printf("\nSetup:\n");
    printf("  # Create macvlan network\n");
    printf("  docker network create -d macvlan \\\n");
    printf("    --subnet=192.168.1.0/24 \\\n");
    printf("    --gateway=192.168.1.1 \\\n");
    printf("    -o parent=eth0 \\\n");
    printf("    mymacvlan\n");
    printf("\n");
    printf("  # Run container\n");
    printf("  docker run --network mymacvlan --ip 192.168.1.200 nginx\n");

    printf("\nNote: Host cannot communicate with macvlan containers\n");
    printf("      (due to how macvlan works at kernel level)\n");
}

// ============================================
// DNS and Service Discovery
// ============================================

void explain_dns(void) {
    printf("\n=== Container DNS ===\n\n");

    printf("User-defined networks have built-in DNS:\n");
    printf("  - Containers can reach each other by name\n");
    printf("  - Automatic service discovery\n");
    printf("  - Docker's embedded DNS server (127.0.0.11)\n");

    printf("\nExample:\n");
    printf("  # Create network\n");
    printf("  docker network create mynet\n");
    printf("\n");
    printf("  # Run containers\n");
    printf("  docker run -d --network mynet --name web nginx\n");
    printf("  docker run -d --network mynet --name app myapp\n");
    printf("\n");
    printf("  # From 'app', can reach 'web' by name\n");
    printf("  docker exec app ping web  # Works!\n");

    printf("\nNote: Default bridge network does NOT have DNS\n");
    printf("      Use --link (deprecated) or user-defined networks\n");
}

// ============================================
// Network Troubleshooting
// ============================================

void explain_troubleshooting(void) {
    printf("\n=== Network Troubleshooting ===\n\n");

    printf("Useful commands:\n\n");

    printf("Inspect networks:\n");
    printf("  docker network ls\n");
    printf("  docker network inspect <network>\n");
    printf("  docker inspect <container> | jq '.[0].NetworkSettings'\n");

    printf("\nContainer networking:\n");
    printf("  docker exec <container> ip addr\n");
    printf("  docker exec <container> ip route\n");
    printf("  docker exec <container> cat /etc/resolv.conf\n");

    printf("\nHost networking:\n");
    printf("  ip addr show docker0\n");
    printf("  brctl show\n");
    printf("  iptables -t nat -L -n -v\n");

    printf("\nConnectivity:\n");
    printf("  docker exec <container> ping <target>\n");
    printf("  docker exec <container> nc -zv <host> <port>\n");
    printf("  docker exec <container> nslookup <hostname>\n");

    printf("\nCapture traffic:\n");
    printf("  # On host, for bridge traffic\n");
    printf("  tcpdump -i docker0 -nn\n");
    printf("  \n");
    printf("  # For specific container\n");
    printf("  docker run --net container:<target> nicolaka/netshoot tcpdump\n");
}

int main(void) {
    explain_networking_modes();
    explain_bridge_network();
    explain_port_mapping();
    explain_host_network();
    explain_none_network();
    explain_overlay_network();
    explain_macvlan();
    explain_dns();
    explain_troubleshooting();

    printf("\n=== Summary ===\n\n");
    printf("+-----------+---------------+---------------------------+\n");
    printf("| Mode      | Isolation     | Use Case                  |\n");
    printf("+-----------+---------------+---------------------------+\n");
    printf("| bridge    | Good          | Default, most apps        |\n");
    printf("| host      | None          | Performance, monitoring   |\n");
    printf("| none      | Complete      | Batch jobs, security      |\n");
    printf("| overlay   | Good          | Multi-host, swarm         |\n");
    printf("| macvlan   | Good          | Legacy apps, direct IP    |\n");
    printf("+-----------+---------------+---------------------------+\n");

    return 0;
}
```

---

## Fichiers

```
ex14/
├── container_networking.h
├── bridge_network.c
├── host_network.c
├── overlay_network.c
├── macvlan.c
├── troubleshooting.c
└── Makefile
```
