# ncloud-certbot-hook

**ncloud-certbot-hook** is a Go-based Certbot hook (for DNS-01 challenges) designed to integrate with [Naver Cloud Platform (NCP)](https://www.ncloud.com/) services. It automatically creates and deletes TXT records in **NCP Global DNS** for domain verification, and registers the issued SSL certificates in **NCP Certificate Manager** after successful issuance/renewal.

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

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/park-jun-woo/ncloud-certbot-hook.git
   cd ncloud-certbot-hook
   ```

2. **Build and Install**:
   Run the following command:
   ```bash
   make
   ```
   This will:
   - Build the binary using `go build`.
   - Move the binary to `/usr/local/bin/`.
   - Install and update required CA certificates.
   - Create a configuration file at `/etc/ncloud-certbot-hook/config.json` (if it does not exist).

## Configuration

Configuration is handled during the `make` process. It will:

- Prompt you to input your `NCP Access Key` and `Secret Key`.
- Generate a configuration file at `/etc/ncloud-certbot-hook/config.json`.

The resulting `config.json` will look like this:
```json
{
  "access_key": "YOUR_NCP_ACCESS_KEY",
  "secret_key": "YOUR_NCP_SECRET_KEY",
  "root_ca_path": "/etc/ssl/certs/ISRG_Root_X1.pem",
  "sleep_time": 30
}
```

Make sure only the user running Certbot can read this file:
```bash
sudo chown root:root /etc/ncloud-certbot-hook/config.json
sudo chmod 600 /etc/ncloud-certbot-hook/config.json
```

If you need to reconfigure the settings, run:
```bash
make config
```

- **access_key**: Your NCP Access Key  
- **secret_key**: Your NCP Secret Key  
- **root_ca_path**: Path to the Let's Encrypt Root CA file. This file ensures secure communication with Let's Encrypt's services.
  ```bash
  sudo apt update
  sudo apt install ca-certificates
  sudo update-ca-certificates
  ```
- **sleep_time**: The duration (in seconds) to pause the execution after adding a DNS record to ensure the record is propagated and recognized across the DNS network before proceeding with the next steps. This helps prevent potential timing issues during DNS validation.

### Permissions

Make sure only the user running Certbot can read this file:
```bash
sudo chown root:root /etc/ncloud-certbot-hook/config.json
sudo chmod 600 /etc/ncloud-certbot-hook/config.json
```

## Usage with Certbot

1. **Install Certbot** on your server (e.g., `apt-get install certbot` on Ubuntu).
2. **Edit your Certbot command** (for DNS-01 challenges), for example:

```bash
sudo ncertbot -d example.com
```

- `--manual-auth-hook`: Invokes **ncloud-certbot-hook** with `--hook=auth`, which creates a TXT record in NCP Global DNS.  
- `--manual-cleanup-hook`: Deletes the TXT record after the domain verification step.  
- `--deploy-hook`: Once the certificate is successfully issued, **ncloud-certbot-hook** uploads it to NCP Certificate Manager.  

Make sure the **paths** match your actual binary location and that your **config file** is set correctly.

## Example

- **Check configuration**:
  ```bash
  ncloud-certbot-hook -config /etc/ncloud-certbot-hook/config.json --hook=auth
  ```
  (It will likely exit with an error if it’s missing environment variables from Certbot, but you can confirm that it can load config and run.)

- **Request certificate**:
  ```bash
  sudo ncertbot -d yourdomain.com -d www.yourdomain.com
  ```
  Follow any on-screen instructions if necessary (`--non-interactive` can skip user prompts).

- **Renew certificates**:
  ```bash
  sudo certbot renew
  ```
  When renewal occurs, the same hooks will run automatically to update DNS and re-register the certificate with NCP if needed.

## License

**ncloud-certbot-hook** is released under the [MIT License](LICENSE).  
See the `LICENSE` file for full license terms.

---

### Feedback & Contributions

Feel free to open [issues](https://parkjunwoo.com/ncloud-certbot-hook/issues) or submit [pull requests](https://parkjunwoo.com/ncloud-certbot-hook/pulls) if you encounter bugs or want to add new features. We welcome all contributions!