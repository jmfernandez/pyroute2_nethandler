# Network event handler based on pyroute2 notifications

This python script is ready to capture events related to IP address assignment and removal on network interfaces.

The captured events are `RTM_NEWADDR`, `RTM_DELADDR` and `RTM_GETADDR` (see [rtnetlink man page](https://man7.org/linux/man-pages/man7/rtnetlink.7.html) for more details).

When any of these events are detected, it tries running the scripts located at [`$XDG_CONFIG_HOME`](https://specifications.freedesktop.org/basedir-spec/latest/#variables)`/pyroute2_nethandler/{event_name}`, passing them as parameter the network interface name where the event happened.