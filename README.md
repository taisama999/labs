# labs

Hands-on verification scripts, empirical benchmarks, security hardening baselines, and technical lab artifacts.
All scripts and data in this repository are tested in real environments rather than relying solely on vendor documentation or unverified AI outputs.

## 📂 Repository Structure

    labs/
    ├── tools/          # Standalone utility & hardening scripts
    ├── benchmarks/     # Empirical measurements & performance CSVs (Coming soon)
    ├── runbooks/       # Operational & disaster recovery checklists (Coming soon)
    └── ai-factchecks/  # Empirical verification logs of LLM outputs (Coming soon)

## 🛠️ Tools & Scripts

| Path | Description | Target Environment | Related Article |
| :--- | :--- | :--- | :--- |
| [`tools/windows11-security.ps1`](./tools/windows11-security.ps1) | Applies Microsoft Defender Secure Score (Defender for Endpoint) security hardening baselines (ASR rules, Credential Guard, BitLocker, SMB/LDAP hardening, etc.). Supports `-AuditModeOnly`. | Windows 11 (Admin) | [Blog Post (JP)](https://www.bigriver.jp/) |

## 🚀 Quick Usage Example

### Windows 11 Defender Secure Score Hardening (`windows11-security.ps1`)

Run PowerShell as **Administrator**:

    # Apply supported rules (such as ASR) in Audit Mode first for safe testing
    .\tools\windows11-security.ps1 -AuditModeOnly

    # Apply full enforcement after validating compatibility
    .\tools\windows11-security.ps1

## ⚠️ Disclaimer

* **Test Before Production:** Scripts and configurations in this repository—especially security hardening baselines—can restrict legacy applications or operational workflows. Always test in a staging environment (or use `-AuditModeOnly` where supported) before deploying to production endpoints.
* **No Warranty:** All materials are provided "as is" under the MIT License without warranty of any kind.

## 🔗 Links

* **Profile:** [@taisama999](https://github.com/taisama999)
* **Technical Blog (JP):** [Alibaba Cloudの備忘ログ](https://www.bigriver.jp/)
* **X (Twitter):** [@taisama9](https://x.com/taisama9)
