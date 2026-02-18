USB device connection history from the registry.
- Key for data exfiltration investigations. Shows what removable storage was connected, when, and by which user.
- Suspicious: USB devices connected during or shortly after the incident window, devices connected during off-hours, new/unknown devices appearing for the first time near suspicious activity.
- Key fields: device serial number, vendor/product, first and last connection times.
- Cross-check: correlate USB connection times with shellbag access to removable media paths and file copy operations in USN journal.
