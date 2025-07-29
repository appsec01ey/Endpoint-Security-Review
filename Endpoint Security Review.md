### Endpoint Security Review 

- An endpoint security review assesses the protections in place for devices like laptops, desktops, mobile phones, and servers (collectively called "endpoints") to ensure they are secure against cyber threats.

#### C1 : Endpoint Controls 

1. List of Installed Applications :
   - Purpose : Review installed applications on an endpoint to identify any unauthorized or non-whitelisted software.
   - Command : Get-Package | Select Name, Version
   - Risk    : Risk of Malwares and Backdoors , increase attack surface

2. 
