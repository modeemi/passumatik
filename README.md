# Passumatik
## About
For changing passwords in Modeemi's environment and syncing the hashes accross the servers.

Hosted on coffee.modeemi.fi

## Updating
First make changes to the repo, then
```
ssh coffee
cd /opt/passumatik
sudo git pull
```

## Installation
Currently (at least once upon a time, 2024-02-01) passumatik is installed on coffee as follows:
* Git repo: `/opt/passumatik/`
* Git deploy key: `/root/passumatik-github-deploy.id_ed25519`

`/root/.ssh/config`
```
# For pulling passumatik
Host github.com-passumatik
        Hostname github.com
        IdentityFile=/root/.ssh/passumatik-github-deploy.id_ed25519
```

`/etc/sudoers.d/passumatik`
```
# Allow running passumatik to all members of modeemi group
%modeemi        ALL=(passumatik)        NOPASSWD: /opt/passumatik/passumatik.py
```

`/usr/local/bin/passumatik` is a symlink to `/opt/passumatik/passumatik.sh`
```
root@coffee:~# ls -lh /usr/local/bin/passumatik
lrwxrwxrwx 1 root root 26 Feb  3 08:03 /usr/local/bin/passumatik -> /opt/passumatik/passumatik.sh
```

