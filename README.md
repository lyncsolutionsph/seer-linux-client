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

The installer asks for the invitation displayed on the SEER VPN page. Input is
hidden and the invitation is not saved. The same invitation may be used to
enroll several devices, while every installation receives unique credentials.

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

## Security notes

- Never paste an invitation into a public issue, chat, screenshot, or command
  line argument.
- The generated device configuration is root-only (`0600`).
- Blocking or deleting the Ubuntu device in SEER revokes its access.
- The public gateway is authenticated before enrollment data is sent.
