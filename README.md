# REST Asymmetric Encryption Demo

This little demo project shows how to:
1. Connect in python to Ciphertrust Manager instance (getting the Bearer Token, etc...).
2. Create an Asymmetric Key Pair (RSA-4096 by default) on Ciphertrust Manager.
3. Retreive Public RSA Key material using Public Key ID.
4. Encrypt locally (on the client) a payload using the RSA Public Key from Ciphertrust Manager.
5. Encrypt remotely (on the Ciphtertrust Manager instance) a payload using the RSA Public Key from Ciphertrust Manager.
6. Decrypt remotely (on the Ciphtertrust Manager instance) previously ancrypted payloads using the RSA Private Key.

## Getting Started

These instructions will give you a copy of the project up and running on
your local machine for development and testing purposes. See deployment
for notes on deploying the project on a live system.

### Prerequisites

Requirements for the software and other tools to build, test and push 
- Build an instance of [Ciphertrust Manager](https://cpl.thalesgroup.com/encryption/ciphertrust-platform-community-edition), the Community Edition will do the job. Contact your local encryption solution dealer or Thales Services Numériques or Thales Cyber Digital Solutions to get the VM image.
- Activate the Community Edition license on Ciphertrust Manager
- Create a "Key Admin" user
- Install python, git, etc...
- Set the right variables in config.py

## License

This project is licensed under the [Apache 2.0](LICENSE) License




