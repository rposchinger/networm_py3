# NetWorm_Py3

Python worm that spreads across local networks.

The worm tries to brute-force root login data and spreads via SSH/SFTP. 
It can be used to measure worm propagation in test networks without real malware. 
The worm has been developed for the evaluation of an MTD (Moving Target Defense) network. 
It is part of a Master’s thesis project at LMU and UniBw M:
[Evaluation of network-level Moving Target Defense Strategies](http://www.nm.ifi.lmu.de/teaching/Ausschreibungen/Diplomarbeiten/ma-network-mtd/)

## Author
Richard Poschinger 

([poschinger.net](https://poschinger.net))

## License

Distributed under the MIT license.

## Usage
### Prerequisites:
Install required packages on all hosts and set INSTALL_REQUIREMENTS to False, if you want to run the tests in an isolated environment without connection to the Internet.

If the hosts have access to the Internet during runtime of the worm, INSTALL_REQUIREMENTS can be set to true. Thus the required resources will be installed during the infection process. 
Still, the requirements need to be installed manually on the host, which acts as the initial attacker. 

```
apt-get install python3 python3-pip unzip nmap iproute2 -y

pip3 install -r requirements.txt
or
pip3 install netifaces python-nmap netaddr paramiko termcolor
```

### Start Worm:
```
python3 networm.py
```

## Legal Advice
THIS REPOSITORY AND EVERY SCRIPT INCLUDED IN IT IS FOR EDUCATIONAL 
AND TESTING PURPOSES ONLY. THE OWNER NOR ANY CONTRIBUTOR IS NOT RESPONSIBLE
FOR YOUR ACTIONS.