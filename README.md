# Test project for parsing Nessus output for package recommendation

This projects consists of the following directories:
- **ansible** - this one serves as ansible home directory and includes the main playbook for deploying a test LAMP configuration on virtual machines.
- **centos-7-lamp** - a directory for Vagrantfile which configures and runs a box with CentOS 7
- **centos-8-lamp** - a directory for Vagrantfile which configures and runs a box with CentOS 8
- **debian-8-lamp** - a directory for Vagrantfile which configures and runs a box with Debian 8
- **package_finder** - a directory with my python script which exports a Nessus scan report and parses its output to find out current vulnerable packages and their alternative version that can fix the possible issues.

---

## TODO for 'package_finder 'python script
---
- Move global constants values to .env
- Add timeout to file export method
- Add exception checkers
- Add various routes to sort out the data
- Add caching logic to avoid requesting and downloading the same report over and over again. 