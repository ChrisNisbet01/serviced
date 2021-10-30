#!/bin/sh /etc/test/service.common

PROG=/etc/test/example.sh
NAME=example

add_service() 
{
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

stop_service() 
{
	serviced_stop "$NAME"
}

start_service() 
{
	serviced_start "$NAME"
}

delete_service() 
{
	serviced_delete "$NAME"
}

