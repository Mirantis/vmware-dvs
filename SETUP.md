Setup ov dev env  that work for me. If you want to use it you will need to customize part of it.

1. `vagrant up --no-provision manager`
1. Login as vagrant:
	1. `sudo apt-get install tmux`
	1. `tmux new -d "sudo ssh guest@172.18.170.94 -L 443:172.16.0.254:443"`
	1. Logout
1. vagrant provision manager
1. http://192.168.51.10/project/access_and_security/ and copy tenant id (i.e.: `7688331961e349dabe0f5bac14f6bf50`)
1. Paste tenant id in fabfile.py under constant `OS_TENANT_ID`)
1. `fab setup`
1. Login as stack and rejoin stack. Then restart neutron server (q-svc screen window)
1. `fab network` to create demo network in vCenter
