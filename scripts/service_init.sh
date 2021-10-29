#!/bin/sh

# A basic serviced 'add' command
# ubus call serviced add ...
#{
#	"name": "example",
#	"stdout": true, 
#	"stderr": true, 
#	"auto_start": true, 
#	"command": ["/home/chris/projects/serviced/example.sh", 100]
#}

START=19
STOP=50

PROG=/etc/test/example.sh
NAME=example

. ./serviced_temp.sh


action=${1:-help}
shift 1

help() {
	cat <<EOF
Syntax: $initscript [command]

Available commands:
	add     Add the service
	start	Start the service
	stop	Stop the service
	delete  Delete the service
	restart	Restart the service
	reload	Reload configuration files (or restart if service does not implement reload)
	enable	Enable service autostart
	disable	Disable service autostart
	enabled	Check if service is started on boot
EOF
}

add() {
	serviced_open
	serviced_name "$NAME"
	serviced_stderr 1
	serviced_stdout 1
	serviced_auto_start 1
	serviced_command_open "$PROG" 100
	serviced_command_close
	serviced_close

	serviced_add
}

stop() {
	serviced_stop "$NAME"
}

start() {
	serviced_start "$NAME"
}

delete() {
	serviced_delete "$NAME"
}

reload() {
	:
}

restart() {
	:
}

running() {
	:
}

status() {
	:
}

enable() {
	:
}

disable() {
	:
}

enabled() {
	:
}

case "$action" in
	add|start|stop|delete|help)
		$action
	;;
esac

