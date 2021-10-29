# Debug allow the path to the json helpers to be overridden from the shell.
[ -z ${JSHN_PATH} ] && JSHN_PATH=/usr/share/libubox
. ${JSHN_PATH}/jshn.sh

trim()
{
    local var="$*"
    # remove leading whitespace characters
    var="${var#"${var%%[![:space:]]*}"}"
    # remove trailing whitespace characters
    var="${var%"${var##*[![:space:]]}"}"
    printf '%s' "$var"
}

serviced_print() 
{
	# Output in 'pretty' format to aid with debugging.
	json_dump -i >&2
}

_serviced_commit() {
	local cmd="$1"

	[ -n "$serviced_DEBUG" ] && serviced_print
	ubus call serviced "$cmd" "$(json_dump)"
	json_cleanup
}

serviced_open()
{
	json_init
}

serviced_close() 
{
	:
}

serviced_add() 
{
	_serviced_commit "add"
}

serviced_delete() 
{
	service_name=$1

	serviced_open
	serviced_name $service_name
	serviced_close
	_serviced_commit "delete"
}

serviced_start() 
{
	service_name=$1

	serviced_open
	serviced_name $service_name
	serviced_close
	_serviced_commit "start"
}

serviced_stop() 
{
	service_name=$1

	serviced_open
	serviced_name $service_name
	serviced_close
	_serviced_commit "stop"
}

serviced_name() 
{
	json_add_string "name" "$(trim $1)"
}

serviced_stderr() 
{
	json_add_boolean "stderr" $(trim $1)
}

serviced_stdout() 
{
	json_add_boolean "stdout" $(trim $1)
}

serviced_auto_start() 
{
	json_add_boolean "auto_start" $(trim $1)
}

serviced_command_param() 
{
	json_add_string "" "$(trim $1)"
}

serviced_command_params() 
{
	for l in "$@"; do
		serviced_command_param "$(trim $l)"
	done
}

serviced_command_open() 
{
	json_add_array "command"
	serviced_command_params "$@"
}

serviced_command_close() 
{
	json_close_array # command
}

