# This document is a how-to for installing a Fedora scripts.mit.edu server.
# It is semi-vaguely in the form of a shell script, but is not really
# runnable as it stands.

# Notation
# [PRODUCTION] Production server that will be put into the pool
# [WIZARD]     Semi-production server that will only have
#              daemon.scripts-security-upd bits, among other
#              restricted permissions
# [TESTSERVER] Completely untrusted server

# 'branch' is the current svn branch you are on.  You want to
# use trunk if your just installing a new server, and branches/fcXX-dev
# if your preparing a server on a new Fedora release.
branch="trunk"

# 'server' is the public hostname of your server, for SCP'ing files
# to and from.
server=YOUR-SERVER-NAME-HERE

# ----------------------------->8--------------------------------------
#                       FIRST TIME INSTRUCTIONS
#
# [PRODUCTION] If this is the first time you've installed this hostname,
# you will need to update a bunch of files to add support for it. These
# include:
#   o Adding it to ansible/inventory.yml in either scripts-real or
#     scripts-real-test
#   o If this is a new distribution, set use_* to false in inventory.yml
#     since none of the scripts packages will be built yet
#   o Adding routing rules for the static IP in
#     /etc/sysconfig/network-scripts/route-eth1
#   o Adding the IP address to the hosts file (same hosts as for
#     scripts-vhost-names)
#   o Put the hostname information in LDAP so SVN and Git work
#   o Set up Nagios monitoring on sipb-noc for the host
#   o Update locker/etc/known_hosts
#   o Update website files:
#       /mit/scripts/web_scripts/home/server.css.cgi
#       /mit/scripts/web_scripts/heartbeat/heartbeat.php
#
# You will also need to prepare the keytabs for credit-card.  In particular,
# use ktutil to combine the host/scripts.mit.edu and
# host/scripts-vhosts.mit.edu keys with host/this-server.mit.edu in
# the keytab.  Do not use 'k5srvutil change' on the combined keytab
# or you'll break the other servers. (real servers only).  Be
# careful about writing out the keytab: if you write it to an
# existing file the keys will just get appended.  The correct
# credential list should look like:
#   ktutil:  l
#   slot KVNO Principal
#   ---- ---- ---------------------------------------------------------------------
#      1    5 host/old-faithful.mit.edu@ATHENA.MIT.EDU
#      2    3 host/scripts-vhosts.mit.edu@ATHENA.MIT.EDU
#      3    2 host/scripts.mit.edu@ATHENA.MIT.EDU
#      4    8 host/scripts-test.mit.edu@ATHENA.MIT.EDU
#
# The LDAP keytab should be by itself, so be sure to delete it and
# put it in its own file.

# ----------------------------->8--------------------------------------
#                      INFINITE INSTALLATION

# Start with a Scripts kickstarted install of Fedora (install-fedora)
# For example,
    remctl xvm-remote control $server install mirror=http://mirrors.mit.edu/fedora/linux/ dist=30 arch=x86_64 ks=https://raw.githubusercontent.com/mit-scripts/scripts/ansible-realserver/server/fedora/ks/kickstart.txt

# [TEST] You'll need to fix some config now.  See bottom of document.

# Check the configuration progress with
    systemctl status ansible-config-me
# You can tail the log with
    journalctl -f -u ansible-config-me
# If the configuration fails, figure out what happened and rerun it with
    systemctl start ansible-config-me

# This is the point at which you should start updating scriptsified
# packages for a new Fedora release.  Consult 'upgrade-tips' for more
# information.

    su scripts-build -
    cd /srv/repository/fedora/server && make all
    cp /var/lib/mock/fedora-*/result/*.rpm /home/scripts-build/mock-local/
    createrepo ~/mock-local/
# Flip the appropriate flag(s) in inventory.yml and rerun ansible
    rm /etc/ansible-config-done
    systemctl start ansible-config-me

# Install the full list of RPMs that users expect to be on the
# scripts.mit.edu servers.
rpm -qa --queryformat "%{Name}.%{Arch}\n" | sort > packages.txt
# arrange for packages.txt to be passed to the server, then run:
    cd /tmp
    yum install -y $(cat packages.txt)

# Check which packages are installed on your new server that are not
# in the snapshot, and remove ones that aren't needed for some reason
# on the new machine.  Otherwise, aside from bloat, you may end up
# with undesirable things for security, like sendmail.
    rpm -qa --queryformat "%{Name}.%{Arch}\n" | grep -v kernel | sort > newpackages.txt
    diff -u packages.txt newpackages.txt | grep -v kernel | less
    # here's a cute script that removes all extra packages
    yum erase -y $(grep -Fxvf packages.txt newpackages.txt)

# ----------------------------->8--------------------------------------
#                       INFINITE CONFIGURATION

# [PROD] Create fedora-ds user (needed for credit-card)
# [TEST] too if you want to run a local dirsrv instance
useradd -r -d /var/lib/dirsrv fedora-ds

# Run credit-card to clone in credentials and make things runabble
# NOTE: You may be tempted to run credit-card earlier in the install
# process in order, for example, to be able to SSH in to the servers
# with Kerberos.  However, it is better to install the credentials
# *after* we have run a boatload untrusted code as part of the
# spheroids objects process.  So don't move this step earlier!
python host.py push $server

# This is superseded by credit-card, which works for [PRODUCTION] and
# [WIZARD].  We don't have an easy way of running credit-card for XVM...
#b
#
#   # All types of servers will have an /etc/daemon.keytab file, however,
#   # different types of server will have different credentials in this
#   # keytab.
#   #   [PRODUCTION] daemon.scripts
#   #   [WIZARD]     daemon.scripts-security-upd
#   #   [TESTSERVER] daemon.scripts-test

# [PRODUCTION] Set up replication (see ./install-ldap).
# You'll need the LDAP keytab for this server: be sure to chown it
# fedora-ds after you create the fedora-ds user
    ls -l /etc/dirsrv/keytab
    cat install-ldap

# Note about OpenAFS: Check that fs sysname is correct.  You should see,
# among others, 'amd64_fedoraX_scripts' (vary X) and 'scripts'. If it's
# not, you probably did a distro upgrade and should update
# tokensys (server/common/oursrc/tokensys/scripts-afsagent-startup.in)
    fs sysname

# Run fmtutil-sys --all, which does something that makes TeX work.
# (Note: this errors on XeTeX which is ok.)
    fmtutil-sys --all

# Check for unwanted setuid/setgid binaries
    find / -xdev -not -perm -o=x -prune -o -type f -perm /ug=s -print | grep -Fxvf /etc/scripts/allowed-setugid.list
    find / -xdev -not -perm -o=x -prune -o -type f -print0 | xargs -0r /usr/sbin/getcap | cut -d' ' -f1 | grep -Fxvf /etc/scripts/allowed-filecaps.list
    # You can prune the first set of binaries using 'chmod u-s' and 'chmod g-s'
    # and remove capabilities using 'setcap -r'

# Reboot the machine to restore a consistent state, in case you
# changed anything. (Note: Starting kdump fails (this is ok))

# ------------------------------->8-------------------------------
#                ADDENDA AND MISCELLANEOUS THINGS

# [OPTIONAL] Your machine's hostname is baked in at install time;
# in the rare case you need to change it: it appears to be in:
#   o /etc/sysconfig/network
#   o your lvm thingies; probably don't need to edit

# [TESTSERVER] Enable password log in
        vim /etc/ssh/sshd_config
        service sshd reload
        vim /etc/pam.d/sshd
# Replace the first auth block with:
#           # If they're not root, but their user exists (success),
#           auth    [success=ignore ignore=ignore default=1]        pam_succeed_if.so uid > 0
#           # print the "You don't have tickets" error:
#           auth    [success=die ignore=reset default=die]  pam_echo.so file=/etc/issue.net.no_tkt
#           # If !(they are root),
#           auth    [success=1 ignore=ignore default=ignore]        pam_succeed_if.so uid eq 0
#           # print the "your account doesn't exist" error:
#           auth    [success=die ignore=reset default=die]  pam_echo.so file=/etc/issue.net.no_user


# [WIZARD/TESTSERVER] If you are setting up a non-production server,
# there are some services that it won't provide, and you will need to
# make it talk to a real server instead.  In particular:
#   - We don't serve the web, so don't bind scripts.mit.edu
#   - We don't serve LDAP, so use another server
# XXX: Someone should write sed scripts to do this
# This involves editing the following files:
        svn rm /etc/sysconfig/network-scripts/ifcfg-lo:{0,1,2,3}
        svn rm /etc/sysconfig/network-scripts/route-eth1 # [TESTSERVER] only
#   o /etc/nslcd.conf
#       replace: uri ldapi://%2fvar%2frun%2fdirsrv%2fslapd-scripts.socket/
#       with: uri ldap://scripts.mit.edu/
#           (what happened to nss-ldapd?)
#   o /etc/openldap/ldap.conf
#       add: URI ldap://scripts.mit.edu/
#            BASE dc=scripts,dc=mit,dc=edu
#   o /etc/httpd/conf.d/vhost_ldap.conf
#       replace: VhostLDAPUrl "ldap://127.0.0.1/ou=VirtualHosts,dc=scripts,dc=mit,dc=edu"
#       with: VhostLDAPUrl "ldap://scripts.mit.edu/ou=VirtualHosts,dc=scripts,dc=mit,dc=edu"
#   o /etc/postfix/virtual-alias-{domains,maps}-ldap.cf
#       replace: server_host ldapi://%2fvar%2frun%2fdirsrv%2fslapd-scripts.socket/
#       with: server_host = ldap://scripts.mit.edu
# to use scripts.mit.edu instead of localhost.

# [WIZARD/TESTSERVER] If you are setting up a non-production server,
# afsagent's cronjob will attempt to be renewing with the wrong
# credentials (daemon.scripts). Change this:
    vim /home/afsagent/renew # replace all mentions of daemon.scripts.mit.edu

# [TESTSERVER]
#   - You need a self-signed SSL cert or Apache will refuse to start
#     or do SSL.  Generate with: (XXX recommended CN?)
    openssl req -new -x509 -sha256 -newkey rsa:2048 -keyout /etc/pki/tls/private/scripts.key -out /etc/pki/tls/certs/scripts-cert.pem -nodes -extensions v3_req
    ln -s /etc/pki/tls/private/scripts.key /etc/pki/tls/private/scripts-2048.key
#     Also make the various public keys match up
    openssl rsa -in /etc/pki/tls/private/scripts.key -pubout > /etc/pki/tls/certs/star.scripts.pem
    openssl rsa -in /etc/pki/tls/private/scripts.key -pubout > /etc/pki/tls/certs/scripts.pem
    openssl rsa -in /etc/pki/tls/private/scripts.key -pubout > /etc/pki/tls/certs/scripts-cert.pem
#     Nuke the CSRs since they will all mismatch
#     XXX alternate strategy replace all the pem's as above
    cd /etc/httpd/vhosts.d
    svn rm *.conf
