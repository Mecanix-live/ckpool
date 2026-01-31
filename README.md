# CKPool - Next-Gen Mining Stratum Server
**High-performance Bitcoin mining stratum server** featuring:

✓ **Dual-Protocol Support: TLS 1.3 (port 3443) & Plaintext (port 3333)
✓ **Encryption**: TLS_AES_256_GCM_SHA384 - 256-bit cipher suite
✓ **Certificate Flexibility (Self-signed, CA-signed, Let's Encrypt and Client certificate verification)
✓ **Upgraded Hardware-Accelerated SHA-256** (SHA-NI + OpenSSL EVP)  
✓ **Modern build system** with CMake integration  
✓ **Using latest/stable JSON/Jansson v2.14.1 library
✓ **Optimized multi-process architecture** for Linux

*"The most efficient and Secured CKPool implementation to date"*

## Prerequisites

- Ubuntu/Debian-based system
- Bitcoin Core fully synced and running
- ZMQ notifications enabled in Bitcoin Core (`zmqpubhashblock=tcp://127.0.0.1:28335`)

## Installation

### 1. Install dependencies:
```bash
sudo apt install git build-essential cmake libssl-dev libjansson-dev libzmq3-dev
```

### 2. Clone, Build and Install CKPool:
```bash
cd ~
git clone https://github.com/Mecanix-live/ckpool.git
sudo chown -R $USER:$USER ckpool
cd ckpool
cmake -B build -DGENERATE_SELF_SIGNED=ON && cmake --build build --parallel
sudo cmake --install build
ckpool --help
```

## Configuration

### Certificates & CA Generation:
```bash
cd ~/ckpool
./scripts/tls-setup.sh --self-signed
./scripts/tls-setup.sh --ca
```

### Create configuration file:
```bash
nano ~/ckpool/ckpool.conf
```
### Example configuration (`ckpool.conf`):
```json
{
  "btcd": [
    {
      "url": "127.0.0.1:8332",
      "auth": "your_rpcuser",
      "pass": "your_rpcpassword"
    }
  ],
  "serverurl": [
    "192.168.10.10:3333",
    "192.168.10.10:3443"
  ],
  "plaintext_enabled": true,
  "plaintext_port": 3333,
  "tls_enabled": true,
  "tls_port": 3443,
  "tls_cert": "/home/mecanix/ckpool/certs/server.crt",
  "tls_key": "/home/mecanix/ckpool/certs/server.key",
  "tls_ca": "/home/mecanix/ckpool/certs/ca.crt",
  "tls_verify": true,
  "btcaddress": "your_btc_address",
  "btcsig": "/mined by nobody/",
  "blockpoll": 100,
  "donation": 0.5,
  "nonce1length": 4,
  "nonce2length": 8,
  "update_interval": 10,
  "version_mask": "1fffe000",
  "mindiff": 512,
  "startdiff": 10000,
  "logdir": "/home/mecanix/ckpool/logs",
  "zmqblock": "tcp://127.0.0.1:28335"
}
```

> **Important:** Replace all placeholder values with your actual configuration:
> - `your_rpcuser` and `your_rpcpassword` with your Bitcoin Core RPC credentials
> - `192.168.10.10:3333` with your own server IP address and port number
> - `your_btc_address` with your mining payout address
> - `/home/mecanix/` with your actual home directory path

## Running CKPool

### Manual Start (Testing):
```bash
ckpool -B -c /home/mecanix/ckpool/ckpool.conf
```

### Automated Service Setup:

1. Create systemd service file:
```bash
sudo nano /etc/systemd/system/ckpool.service
```

2. Example configuration (adjust user/group and path as needed):
```ini
[Unit]
Description=CKPool Stratum
Wants=network-online.target
Requires=bitcoind.service
After=bitcoind.service

[Service]
User=mecanix
Group=mecanix
Type=simple
### -l loglevel 3 (default 5)
ExecStart=ckpool -l 3 -B -c /home/mecanix/ckpool/ckpool.conf
Restart=on-failure
TimeoutStartSec=infinity
TimeoutStopSec=600

[Install]
WantedBy=multi-user.target
```

3. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ckpool
sudo systemctl start ckpool
systemctl status ckpool
sudo systemctl stop ckpool
```

To uninstall ckpool:
```bash
sudo cmake --build build --target uninstall
```

## Notes

- The configuration file path must be absolute when running as a service
- Mining rewards will go to the specified `btcaddress`
- Default log location: `~/ckpool/logs/`
- Recommended to run under a dedicated user account

## Credits:
CKPOOL (by Con Kolivas) is code provided free of charge under the GPLv3 license but its development
is mostly paid for by commissioned funding, and the pool by default contributes
0.5% of solved blocks in pool mode to the development team. Please consider leaving
this contribution in the code if you are running it on a pool or contributing to the
authors listed in AUTHORS if you use this code to aid funding further development.

LICENSE: GNU Public license V3. See included LICENSE for details.
