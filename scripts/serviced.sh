. "/usr/share/libubox/jshn.sh"

serviced_RELOAD_DELAY=1000
_serviced_SERVICE=
_serviced_ubus_socket=/var/run/ubus_led.sh

serviced_lock() {
	local basescript=$(readlink "$initscript")
	local service_name="$(basename ${basescript:-$initscript})"

	flock -n 1000 &> /dev/null
	if [ "$?" != "0" ]; then
		exec 1000>"/var/lock/serviced_${service_name}.lock"
		flock 1000
		if [ "$?" != "0" ]; then
			logger "warning: serviced flock for $service_name failed"
		fi
	fi
}

_serviced_ubus_call() {
	local cmd="$1"

	[ -n "$serviced_DEBUG" ] && json_dump >&2
	ubus call service "$cmd" "$(json_dump)"
	json_cleanup
}

_serviced_open_service() {
	local name="$1"
	local script="$2"

	_serviced_SERVICE="$name"
	_serviced_INSTANCE_SEQ=0

	json_init
	json_add_string name "$name"
	[ -n "$script" ] && json_add_string script "$script"
	json_add_object instances
}

_serviced_close_service() {
	json_close_object
	_serviced_ubus_call ${1:-set}
}

_serviced_add_array_data() {
	while [ "$#" -gt 0 ]; do
		json_add_string "" "$1"
		shift
	done
}

_serviced_add_array() {
	json_add_array "$1"
	shift
	_serviced_add_array_data "$@"
	json_close_array
}

_serviced_add_table_data() {
	while [ -n "$1" ]; do
		local var="${1%%=*}"
		local val="${1#*=}"
		[ "$1" = "$val" ] && val=
		json_add_string "$var" "$val"
		shift
	done
}

_serviced_add_table() {
	json_add_object "$1"
	shift
	_serviced_add_table_data "$@"
	json_close_object
}

_serviced_open_instance() {
	local name="$1"; shift

	_serviced_INSTANCE_SEQ="$(($_serviced_INSTANCE_SEQ + 1))"
	name="${name:-instance$_serviced_INSTANCE_SEQ}"
	json_add_object "$name"
}

_serviced_set_param() {
	local type="$1"; shift

	case "$type" in
		error)
			json_add_array "$type"
			json_add_string "" "$@"
			json_close_array
		;;
		nice|term_timeout)
			json_add_int "$type" "$1"
		;;
		reload_signal)
			json_add_int "$type" $(kill -l "$1")
		;;
		pidfile|user|group|seccomp|capabilities|facility|\
		extroot|overlaydir|tmpoverlaysize)
			json_add_string "$type" "$1"
		;;
		stdout|stderr|no_new_privs)
			json_add_boolean "$type" "$1"
		;;
	esac
}

_serviced_add_timeout() {
	[ "$serviced_RELOAD_DELAY" -gt 0 ] && json_add_int "" "$serviced_RELOAD_DELAY"
	return 0
}

_serviced_append_param() {
	local type="$1"; shift
	local _json_no_warning=1

	json_select "$type"
	[ $? = 0 ] || {
		_serviced_set_param "$type" "$@"
		return
	}
	case "$type" in
		env|data|limits)
			_serviced_add_table_data "$@"
		;;
		command|netdev|file|respawn|watch)
			_serviced_add_array_data "$@"
		;;
		error)
			json_add_string "" "$@"
		;;
	esac
	json_select ..
}

_serviced_close_instance() {
	_json_no_warning=1
	json_close_object
}

_serviced_add_instance() {
	_serviced_open_instance
	_serviced_set_param command "$@"
	_serviced_close_instance
}

serviced_running() {
	local service="$1"
	local instance="${2:-*}"
	[ "$instance" = "*" ] || instance="'$instance'"

	json_init
	json_add_string name "$service"
	local running=$(_serviced_ubus_call list | jsonfilter -l 1 -e "@['$service'].instances[$instance].running")

	[ "$running" = "true" ]
}

_serviced_kill() {
	local service="$1"
	local instance="$2"

	json_init
	[ -n "$service" ] && json_add_string name "$service"
	[ -n "$instance" ] && json_add_string instance "$instance"
	_serviced_ubus_call delete
}

_serviced_status() {
	local service="$1"
	local instance="$2"
	local data

	json_init
	[ -n "$service" ] && json_add_string name "$service"

	data=$(_serviced_ubus_call list | jsonfilter -e '@["'"$service"'"]')
	[ -z "$data" ] && { echo "inactive"; return 3; }

	data=$(echo "$data" | jsonfilter -e '$.instances')
	if [ -z "$data" ]; then
		[ -z "$instance" ] && { echo "active with no instances"; return 0; }
		data="[]"
	fi

	[ -n "$instance" ] && instance="\"$instance\"" || instance='*'
	if [ -z "$(echo "$data" | jsonfilter -e '$['"$instance"']')" ]; then
		echo "unknown instance $instance"; return 4
	else
		echo "running"; return 0
	fi
}

_serviced_wrapper \
	serviced_open_service \
	serviced_close_service \
	serviced_add_instance \
	serviced_open_instance \
	serviced_close_instance \
	serviced_set_param \
	serviced_append_param

