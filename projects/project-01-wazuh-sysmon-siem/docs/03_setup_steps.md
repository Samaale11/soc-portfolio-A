## Build log

### Step 1: Ubuntu Server ISO downloaded
- Version: Ubuntu Server 24.04 LTS
- ISO filename: ubuntu-24.04.4-live-server-amd64
- Saved path on Windows: "C:\ISO\UbuntuServer\ubuntu-24.04.4-live-server-amd64.iso"
### Step 2: Host-only network created
- Host-only network name: VirtualBox Host-Only Ethernet Adapter
- Host-only network IPv4 : 192.168.172.1
### Step 3: Ubuntu VM created
- VM name: ubuntu-wazuh-soc
- CPU:  4cores
- RAM: 16 GB
- Disk: 60 GB
- Adapter 1: NAT
- Adapter 2: Host-only (name: VirtualBox Host-Only Ethernet Adapter)
- ### Step 4: Ubuntu installed
- Ubuntu version installed: 24.04.4 LTS
- Username created: farah
- OpenSSH server: enabled: yes
### step 5. Docker installation verification
- Docker Engine install method: Docker official apt repository (Ubuntu)
- Docker version output:  29.2.1
- Docker Compose plugin version output:  v5.0.2
