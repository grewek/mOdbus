package main

import "core:log"
import "core:net"
import "core:os"
import "core:time"
import "modbus"

MODBUS_TCP_MAX_FRAME_SIZE :: 260


TcpConnection :: struct {
	socket:        net.TCP_Socket,
	timeout:       time.Duration,
	// A Frame that is received by a TCP Socket can only contain a maximum
	// of 260 bytes, which means that this buffer can house one frame and a bit more in
	// the worst case.
	// NOTE: __check__ that if we use async or threads later
	// there is no way for the user to write data behind the buffer.
	buffer:        [512]u8,
	buffer_length: int,
	state:         ConnectionState,
}

ConnectionAction :: enum {
	Success,
	Retry,
	Close,
}

try_extract_frame :: proc(connection: ^TcpConnection, request_frame: []u8) -> ConnectionAction {
	frame_size, frame_valid := modbus.validate_frame(connection.buffer[0:connection.buffer_length])

	if frame_valid == .Incomplete {
		return .Retry
	}

	if frame_valid == .Invalid {
		return .Close
	}

	if frame_valid == .Validated {
		//Copy the validated frame
		copy(request_frame, connection.buffer[0:frame_size])

		//Remove the data from the sockert data buffer
		copy_slice(connection.buffer[0:], connection.buffer[frame_size:connection.buffer_length])
		connection.buffer_length -= frame_size
	}

	return .Success
}


tcp_send_modbus_frame :: proc(frame: []u8, connection: ^TcpConnection) -> bool {
	byte_send_count: int = 0
	for byte_send_count < len(frame) {
		bytes_send, send_error := net.send_tcp(connection.socket, frame[byte_send_count:])
		if send_error != .None {
			log.error("cannot send data")
			return false
		}

		if bytes_send == 0 {
			log.error("could not send data, disconnecting client")
			return false
		}


		byte_send_count += bytes_send
	}

	return true
}

ConnectionState :: enum {
	Open,
	Aborted,
	Closed,
}

handle_connection :: proc(connection: ^TcpConnection, request_frame: []u8) -> ConnectionState {
	for {
		processing_state := try_extract_frame(connection, request_frame)

		if processing_state == .Success {
			return .Open
		}
		if processing_state == .Close {
			return .Aborted
		}

		bytes_received, err_received := net.recv_tcp(
			connection.socket,
			connection.buffer[connection.buffer_length:],
		)
		connection.buffer_length += bytes_received

		if err_received != .None {
			return .Aborted
		}

		if bytes_received == 0 {
			return .Closed
		}
	}
}

CONNECTION_TIMEOUT_IN_SECS :: 5

TcpInitializationError :: enum {
	None,
	ConnectionRefused,
	SetTimeoutFailure,
}
initialize_tcp_connection :: proc(
	listening_socket: net.TCP_Socket,
	connection: ^TcpConnection,
) -> TcpInitializationError {
	incoming_connection, from, err_accept := net.accept_tcp(listening_socket)
	if err_accept != .None {
		return .ConnectionRefused
	}

	connection.socket = incoming_connection
	sock_option_error := net.set_option(connection.socket, .Receive_Timeout, connection.timeout)
	if sock_option_error != .None {
		net.close(connection.socket)
		connection.state = .Closed
		connection.buffer_length = 0
		return .SetTimeoutFailure
	}

	connection.buffer_length = 0
	connection.state = .Open
	return .None
}
main :: proc() {

	context.logger = log.create_console_logger()
	address := "127.0.0.1"
	port := 10502

	local_address, ok := net.parse_ip4_address(address)
	if !ok {
		log.infof("%v is not a valid ip address", address)
		os.exit(1)
	}

	endpoint := net.Endpoint {
		address = local_address,
		port    = port,
	}

	sock, err := net.listen_tcp(endpoint)
	if err != nil {
		log.errorf("cannot start socket: %v", err)
		os.exit(1)
	}

	defer net.close(sock)

	log.infof("Server listening on \"%v:%v\"", address, port)

	connection: TcpConnection = {
		state         = .Closed,
		timeout       = time.Second * CONNECTION_TIMEOUT_IN_SECS,
		buffer        = {},
		buffer_length = 0,
	}

	for {
		if connection.state == .Closed {
			connection_error := initialize_tcp_connection(sock, &connection)

			if connection_error != .None {
				log.infof("error: %v", connection_error)
				continue
			}
		}


		if connection.state == .Open {
			request_frame: [260]u8
			next_state := handle_connection(&connection, request_frame[:])
			if next_state == .Aborted || next_state == .Closed {
				log.infof("Closing connection")
				net.close(connection.socket)
				connection.state = .Closed
				continue
			}

			parsed_modbus_request, parser_error := modbus.parse_request_frame(request_frame[:])
			log.infof("request: %v", parsed_modbus_request)
		}

	}
}
