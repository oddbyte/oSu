# oSu
New su binary. Made to replace su.
Requires Linux Kernel 5.9 or above.
Requires libcap to install.

## Installation:
To install run:
```
curl -sSL https://raw.githubusercontent.com/oddbyte/oSu/main/installer | sudo bash
```
In bash.
Then, as root, run `osu` to make the config file at `/etc/osu.conf`

## Config:
```
# oSu configuration file.

PATH-SECURE = { /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin } # PATH is automatically set to this upon running.

# You can use UIDs and GIDs:
user-[0] allow-caps all NOPASSWD
group-[0] allow-caps all NOPASSWD
# You can also use user / group names:
# group-[wheel] allow-caps all
# You can set specific capabilities to allow:
# user-[oddbyte] allow-caps cap_dac_override,cap_chown
# You can also deny certain ones:
# group-[oddbyte] allow-caps all deny-caps cap_sys_admin,cap_bpf
# The override specification should go like this, from most important (overrides lowers) to least important:

# User Deny
# Primary group deny
# User Allow
# Primary group allow
# Supplemental group deny
# Supplemental group allow

# Example:
# User oddbyte with group oddbyte and supplemental groups users and wheel runs osu
# The config has user-[oddbyte] allow-caps cap_dac_override,cap_chown and group-[oddbyte] allow-caps all deny-caps cap_sys_admin,cap_bpf and group-[wheel] allow-caps all
# This translates into: allow everything except cap_sys_admin,cap_bpf (group wheel allows all, but the primary group (oddbyte) is denying cap_sys_admin,cap_bpf)
```

## Usage:
```
oddbyte@oddbyte:~$ osu --help
Usage:
 osu [options]

Options:
 --preserve-path                     don't reset path to PATH-SECURE
 -w, --whitelist-environment <list>  don't reset specified variables (If Path is included in this, it is ignored. Use --preserve-path instead.)

 -u, --user <user>                   specify the user
 -g, --group <group>                 specify the primary group
 -G, --supp-group <group>            specify a supplemental group

 -l, --login                         make the shell a login shell
 --set-caps <list>                   only set the specified capabilities (only if you have access to them. Run osu --what-can-i-do to see all capabilities you are allowed to use.)
 -c, --command <command>             pass a command to the shell with -c
                                     please make sure to enclose any commands that require spaces in double quotes ("")
                                     also, please escape any double quotes in the command like so: (\")
 --session-command <command>         pass a command to the shell with -c and do not create a new session
 -P, --pty                           create a new pseudo-terminal

 --debug                             display debug messages all steps of the way
 --drop                              drop all privs and capabilities, and set no-new-privs
 -h, --help                          display this help
 --what-can-i-do                     display what capabilities you can 
 -V, --version                       display version

Examples:
 osu
 osu -c sh
 osu --drop
 osu -u root -g 0 -G users,106 -c "echo \"hello\""

osu version 1.1
oSu author: Oddbyte (https://oddbyte.dev)
```

# Manual Installation:

## Building:
To build you will need to install libcap and libcap-dev:
```
sudo apt install libcap2 libcap2-bin libcap-dev libpam0g-dev -y
```
To build just run:
```
sudo gcc -o /usr/local/bin/osu osu.c -lcap -lutil -lpam -lpam_misc
```

## Setup:
After building the binary run:
```
sudo chmod 555 /usr/local/bin/osu
sudo setcap "all=eip" /usr/local/bin/osu
```
