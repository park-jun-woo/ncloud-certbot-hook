# ncp-certbot-hook

**ncp-certbot-hook** is a Go-based Certbot hook (for DNS-01 challenges) designed to integrate with [Naver Cloud Platform (NCP)](https://www.ncloud.com/) services. It automatically creates and deletes TXT records in **NCP Global DNS** for domain verification, and registers the issued SSL certificates in **NCP Certificate Manager** after successful issuance/renewal.

## Features

1. **DNS-01 Challenge Automation**  
   - Automatically adds `_acme-challenge.<domain>` TXT records to NCP Global DNS (`auth-hook`)  
   - Cleans them up after verification (`cleanup-hook`)  

2. **NCP Certificate Manager Registration**  
   - Once a certificate is successfully issued (or renewed), it is automatically uploaded to NCP Certificate Manager (`deploy-hook`).  

3. **No Service Downtime**  
   - By using DNS-01 challenges, certificates can be issued or renewed without interrupting your running services.  

## Table of Contents

- [Requirements](#requirements)  
- [Installation](#installation)  
- [Configuration](#configuration)  
- [Usage with Certbot](#usage-with-certbot)  
- [Example](#example)  
- [License](#license)

## Requirements

- **Go 1.18+** (or any reasonably recent Go version)
- **Certbot** (installed on your server)
- **Naver Cloud Platform** account with API access enabled:
  - **Global DNS** service activated
  - **Certificate Manager** activated
  - **API Gateway** credentials (Access Key, Secret Key)
- A valid domain you manage via **NCP Global DNS** (or plan to manage)

## Installation

1. **Clone or Download** the repository:
   ```bash
   git clone https://github.com/park-jun-woo/ncp-certbot-hook.git
   cd ncp-certbot-hook
   ```

2. **Build** the binary:
   ```bash
   go build -o ncp-certbot-hook ncp-certbot-hook.go
   ```
   This produces the executable **ncp-certbot-hook**.

3. **Move** the binary to a system-wide location (optional):
   ```bash
   sudo mv ncp-certbot-hook /usr/local/bin/
   sudo chmod +x /usr/local/bin/ncp-certbot-hook
   ```
   Now you can run `ncp-certbot-hook` from anywhere.

## Configuration

By default, **ncp-certbot-hook** looks for a config file under:  
```
/etc/certhook/config.json
```
You can specify a custom path with the `-config` flag.

### config.json Format

```json
{
  "access_key": "YOUR_NCP_ACCESS_KEY",
  "secret_key": "YOUR_NCP_SECRET_KEY",
  "sleep_time": 30
}
```

- **access_key**: Your NCP Access Key  
- **secret_key**: Your NCP Secret Key  
- **sleep_time**: The duration (in seconds) to pause the execution after adding a DNS record to ensure the record is propagated and recognized across the DNS network before proceeding with the next steps. This helps prevent potential timing issues during DNS validation.

### Permissions

Make sure only the user running Certbot can read this file:
```bash
sudo chown root:root /etc/certhook/config.json
sudo chmod 600 /etc/certhook/config.json
```

## Usage with Certbot

1. **Install Certbot** on your server (e.g., `apt-get install certbot` on Ubuntu).
2. **Edit your Certbot command** (for DNS-01 challenges), for example:

```bash
sudo certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook "/usr/local/bin/ncp-certbot-hook --hook=auth" \
  --manual-cleanup-hook "/usr/local/bin/ncp-certbot-hook --hook=cleanup" \
  --deploy-hook "/usr/local/bin/ncp-certbot-hook --hook=deploy" \
  --non-interactive --agree-tos --manual-public-ip-logging-ok \
  -d example.com
```

- `--manual-auth-hook`: Invokes **ncp-certbot-hook** with `--hook=auth`, which creates a TXT record in NCP Global DNS.  
- `--manual-cleanup-hook`: Deletes the TXT record after the domain verification step.  
- `--deploy-hook`: Once the certificate is successfully issued, **ncp-certbot-hook** uploads it to NCP Certificate Manager.  

Make sure the **paths** match your actual binary location and that your **config file** is set correctly.

## Example

- **Check configuration**:
  ```bash
  ncp-certbot-hook -config /etc/certhook/config.json --hook=auth
  ```
  (It will likely exit with an error if it’s missing environment variables from Certbot, but you can confirm that it can load config and run.)

- **Request certificate**:
  ```bash
  sudo certbot certonly \
    --manual \
    --preferred-challenges dns \
    --manual-auth-hook "/usr/local/bin/ncp-certbot-hook --hook=auth" \
    --manual-cleanup-hook "/usr/local/bin/ncp-certbot-hook --hook=cleanup" \
    --deploy-hook "/usr/local/bin/ncp-certbot-hook --hook=deploy" \
    -d yourdomain.com -d www.yourdomain.com
  ```
  Follow any on-screen instructions if necessary (`--non-interactive` can skip user prompts).

- **Renew certificates**:
  ```bash
  sudo certbot renew
  ```
  When renewal occurs, the same hooks will run automatically to update DNS and re-register the certificate with NCP if needed.

## License

**ncp-certbot-hook** is released under the [MIT License](LICENSE).  
See the `LICENSE` file for full license terms.

---

### Feedback & Contributions

Feel free to open [issues](https://github.com/park-jun-woo/ncp-certbot-hook/issues) or submit [pull requests](https://github.com/park-jun-woo/ncp-certbot-hook/pulls) if you encounter bugs or want to add new features. We welcome all contributions!