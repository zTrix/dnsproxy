# project origin

To use google's blocked services in China, we can point them to beijing IP to fuck the G~F~W, the simplest way is to use the hosts file, but the hosts file is not dynamic, and wildcard match or regex match are not supported.

This simple dnsproxy is written to solve this problem.

Also, it's a dnsproxy, with which you can easily make your own A record conveniently.

It's rewritten from my network security course homework.

# dependency
python2 is needed to run

# configuration
Most time you can run the program directly without configuration.

To add custom configuration, modify the dnsproxy.conf file. The syntax is simple:
options:
    name = value
localrules:
    localrule <ip> <pattern> [re]

# run
./dnsproxy.py
