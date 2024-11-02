# oSu
New su binary. Made to replace su.
Requires Linux Kernel 5.9 or above.
Requires libcap to install.

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

## Usage:
```
oddbyte@oddbyte:~$ osu --help
Usage:
 osu [options]

Options:
 -m, -p, --preserve-environment      do not reset environment variables (Path is reset unless --preserve-path is set)
 --preserve-path                     don't reset path to PATH-SECURE
 -w, --whitelist-environment <list>  don't reset specified variables (If Path is included in this, it is ignored. Use --preserve-path instead.)

 -u, --user <user>                   specify the user
 -g, --group <group>                 specify the primary group
 -G, --supp-group <group>            specify a supplemental group

 -l, --login                      make the shell a login shell
 --set-caps <list>                   only set the specified capabilities (only if you have access to them. Run osu --what-can-i-do to see all capabilities you are allowed to use.)
 -c, --command <command>             pass a command to the shell with -c
                                     please make sure to enclose any commands that require spaces in double quotes ("")
                                     also, please escape any double quotes in the command like so: (\")
 --session-command <command>         pass a command to the shell with -c and do not create a new session
 -P, --pty                           create a new pseudo-terminal

 --debug                             display debug messages all steps of the way
 -h, --help                          display this help
 --what-can-i-do                     display what capabilities you can
 -V, --version                       display version

Examples:
 osu
 osu -c sh
 osu -u root -g 0 -G users,106 -c "echo \"hello\""

osu version 1.0
oSu author: Oddbyte (https://oddbyte.dev)
```
