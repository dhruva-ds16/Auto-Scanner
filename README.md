# Auto-Scanning
Automated scanner for CTF-like boxes
## Scans
* Operating System
* Open Ports
* Services associated with the port (Not complete)
* Directory Busting
* Nikto Scans
* SMB Enumeration
* LDAP Enumeration
* RPC Enumeration
* SMTP Enumeration
* More functionality added in the future

## Requirements:
* Nmap
* Impacket
* OpenVAS
## For vulnerability scans, we use OpenVAS, which requires some additional configurations,

To install the `gvm` package, which provides the `gvm-cli` command-line interface for OpenVAS, run the following command:

```shell
pip install gvm-tools
```

To configure OpenVAS, execute the following commands:

```shell
gvm-cli socket --xml ~/.config/gvm/gvmd.sock
gvm-cli md --create --name "My Scan Config" --target "127.0.0.1" --port "1-65535" --checks "Full and Fast Ultimate" --xml ~/.config/gvm/my_scan_config.xml
```

Make sure to replace `"127.0.0.1"` with the target IP address or hostname you want to scan.
