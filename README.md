# WRARServ

## Introduction
`WRARServ` is a userland controller for an anti-ransomware kernel mode driver, written in C#. It serves as a critical decision-making component that instructs the kernel mode driver whether to permit write operations. By verifying signatures and checking the pre-existence of files, `WRARServ` ensures that only legitimate processes are allowed to modify system data.

## Features
•  [**Signature Verification**]: Checks the digital signatures of files to verify their authenticity.

•  [**Pre-existence Check**]: Determines if a file has existed previously to prevent unauthorized modifications.

•  [**Exclusion Rules**]: Allows users to set exclusion parameters based on permissions and settings, providing flexibility in operation.

•  [**User Permissions**]: Integrates with the system's user permissions to manage write access effectively.


## Getting Started
Clone the repository to your local machine to start using `WRARServ`:

```bash
git clone https://github.com/mostafa-technet/WRARServ.git

Prerequisites
•  Windows operating system with kernel mode driver installed

•  .NET Framework compatible with C# WinForms

Usage
1. 
Start WRARServ.
2. 
Configure the settings according to your security requirements.
3. 
Monitor the application to view allowed and blocked write operations.

Contributing
Contributions to WRARServ are highly encouraged. Please read the contributing guidelines for more information on how to submit pull requests or report issues.

License
This project is open-source and available under the MIT License. See the LICENSE file for more details.

Acknowledgments
•  The cybersecurity community for their invaluable insights

•  All contributors who help maintain and improve WRARServ


Make sure to replace `yourusername` with your actual GitHub username. You can also customize the sections to better fit the specifics of your project and its documentation needs.
