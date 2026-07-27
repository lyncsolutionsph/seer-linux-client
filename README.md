# SEER Linux Client

This client adds an Ubuntu desktop or server to an approved SEER Virtual Private
Network. Each installation receives its own identity and private address,
reports its Linux hostname/model to the SEER VPN page, and reconnects
automatically after a reboot.

## Install on Ubuntu

Supported releases: Ubuntu Server/Desktop 22.04 LTS and 24.04 LTS.

```bash
git clone https://github.com/lyncsolutionsph/seer-linux-client.git
cd seer-linux-client
sudo bash ./install.sh
```

The installer asks for the 15-character alphanumeric invitation displayed on
the SEER VPN page. Input is hidden and the invitation is not saved. The same
invitation may be used to enroll several devices, while every installation
receives unique credentials. It also installs and starts SSH, permits SSH from
the SEER private network when UFW is active, and enables both services after
every reboot. No additional service commands are required after installation.

For an Ubuntu file server with UFW enabled, use:

```bash
sudo bash ./install.sh --allow-file-sharing
```

That option opens only TCP port 445 and only to approved SEER private-network
addresses. It does not install or modify Samba and will not expose the share to
the public internet.

## Connect to the file server

Display the Ubuntu server's private address:

```bash
sudo seer-client address
```

From another connected device, open the existing file share using:

```text
smb://PRIVATE_ADDRESS/SHARE_NAME
```

Example: `smb://10.8.0.3/shared`

The Ubuntu server also appears in **VPN > Connected Devices**. Its Device
Details window shows the same private address.

Connect from another device while that device is connected to SEER:

```bash
ssh YOUR_UBUNTU_USERNAME@PRIVATE_ADDRESS
```

Use the regular Ubuntu account created for the server. Ubuntu normally disables
direct SSH login as `root`.

## Everyday commands

```bash
sudo seer-client status
sudo seer-client restart
sudo seer-client disconnect
sudo seer-client connect
sudo journalctl -u seer-client -n 100 --no-pager
```

`disconnect` also disables start-after-boot. `connect` enables it again.

## Reinstall or move to a replacement gateway

Clone the replacement repository and run `sudo bash ./install.sh` with its
new invitation. The stable installation identity is reused, so the same Ubuntu
server is updated instead of creating a duplicate device.

## Repair an existing installation

These commands are not part of a normal installation. To update or repair an
existing installation, pull the latest release and rerun the same installer:

```bash
cd ~/seer-linux-client
git pull --ff-only
sudo bash ./install.sh
```

The installer detects the existing enrollment and keeps the same device
identity without requesting another invitation. Use `--reenroll` only when
intentionally moving the device to a replacement SEER server.

If an `Operation not permitted` error continues, confirm whether Ubuntu itself
is allowed to administer network interfaces:

```bash
sudo systemd-detect-virt
sudo ip link add seer-permission-check type dummy
sudo ip link delete seer-permission-check
```

If the test interface cannot be created, the Ubuntu installation is running
inside a restricted virtual machine or container. Enable network-administrator
capability for that guest on its host, then restart `seer-client.service`.

## Security notes

- Never paste an invitation into a public issue, chat, screenshot, or command
  line argument.
- The generated device configuration is root-only (`0600`).
- Blocking or deleting the Ubuntu device in SEER revokes its access.
- The public gateway is authenticated before enrollment data is sent.
