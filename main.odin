package main

import "core:encoding/endian"
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

try_extract_frame :: proc(
	connection: ^TcpConnection,
	request_frame: []u8,
) -> (
	int,
	ConnectionAction,
) {
	frame_size, frame_valid := modbus.validate_frame(connection.buffer[0:connection.buffer_length])

	if frame_valid == .Incomplete {
		return 0, .Retry
	}

	if frame_valid == .Invalid {
		return 0, .Close
	}

	if frame_valid == .Validated {
		//Copy the validated frame
		copy(request_frame, connection.buffer[0:frame_size])

		//Remove the data from the sockert data buffer
		copy_slice(connection.buffer[0:], connection.buffer[frame_size:connection.buffer_length])
		connection.buffer_length -= frame_size
	}

	return frame_size, .Success
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

handle_connection :: proc(
	connection: ^TcpConnection,
	request_frame: []u8,
) -> (
	int,
	ConnectionState,
) {
	for {
		processed_frame_size, processing_state := try_extract_frame(connection, request_frame)

		if processing_state == .Success {
			return processed_frame_size, .Open
		}
		if processing_state == .Close {
			return processed_frame_size, .Aborted
		}

		bytes_received, err_received := net.recv_tcp(
			connection.socket,
			connection.buffer[connection.buffer_length:],
		)
		connection.buffer_length += bytes_received

		if err_received != .None {
			return processed_frame_size, .Aborted
		}

		if bytes_received == 0 {
			return processed_frame_size, .Closed
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

Datapoints :: struct {
	holding_registers: [120]u16,
}

fc_read_holding_registers_handler :: proc(
	server: ^Datapoints,
	start: u16,
	quantity: u16,
	out_data: []u16,
) -> modbus.ModbusExceptionCode {
	if int(start) + int(quantity) > len(server.holding_registers) {
		return .IllegalDataAddress
	}

	assert(
		int(quantity) <= len(out_data),
		"out_data buffer is too small to hold the resulting amount of registers",
	)
	copy_slice(out_data, server.holding_registers[start:start + quantity])

	return .None
}

fc_write_single_holding_register :: proc(
	server: ^Datapoints,
	address: u16,
	value: u16,
) -> modbus.ModbusExceptionCode {
	if int(address) >= len(server.holding_registers) {
		return .IllegalDataAddress
	}

	server.holding_registers[address] = value

	return .None
}

framewriter_generate_exception :: proc(
	request_header: modbus.ModbusHeader,
	function_code: u8,
	exception: modbus.ModbusExceptionCode,
	response_frame: []u8,
) -> int {
	exception_function_code: u8 = function_code | 0x80
	mbap_length: u16 = modbus.MODBUS_EXCEPTION_FRAME_PAYLOAD_LENGTH

	//Write MBAP Header
	framewriter_write_header(request_header, mbap_length, response_frame)

	//Write exception payload, all Payloads are supported.
	response_frame[modbus.FUNCTION_CODE_OFFSET_IN_FRAME] = exception_function_code
	response_frame[modbus.EXCEPTION_FIELD_OFFSET_IN_FRAME] = u8(exception)

	return (modbus.MBAP_HEADER_SIZE_WITHOUT_UNIT_ID) + int(mbap_length)
}

framewriter_write_header :: proc(
	header: modbus.ModbusHeader,
	mbap_length: u16,
	response_frame: []u8,
) {
	_ = endian.put_u16(
		response_frame[modbus.TRANSACTION_ID_OFFSET_IN_FRAME:],
		.Big,
		header.transaction_id,
	)
	_ = endian.put_u16(
		response_frame[modbus.PROTOCOL_ID_OFFSET_IN_FRAME:],
		.Big,
		header.protocol_id,
	)
	_ = endian.put_u16(response_frame[modbus.LENGTH_FIELD_OFFSET_IN_FRAME:], .Big, mbap_length)
	response_frame[modbus.UNIT_ID_OFFSET_IN_FRAME] = header.unit_id
}

//TODO: Only works for FC 3 at the moment
framewriter_generate_fc3_response :: proc(
	request_header: modbus.ModbusHeader,
	function_code: u8,
	data: []u16,
	response_frame: []u8,
) -> int {
	mbap_length: u16 = 3 + u16(len(data) * 2)
	//Write MBAP Header
	framewriter_write_header(request_header, mbap_length, response_frame)

	//Write Payload, this is specific to the actual requested function. Currently we only support fc3
	response_frame[modbus.FUNCTION_CODE_OFFSET_IN_FRAME] = function_code

	//Write Length of data into response frame
	//TODO: Extract the number so that the intent is clear modbus.DATA_LENGTH_OFFSET_IN_FRAME or something.
	response_frame[8] = u8(len(data) * 2)

	start_of_data_offset := 9
	next_start := 0
	for value in data {
		_ = endian.put_u16(response_frame[(start_of_data_offset + next_start):], .Big, value)
		next_start += 2
	}

	return modbus.MBAP_HEADER_SIZE_WITHOUT_UNIT_ID + int(mbap_length)
}

framewriter_generate_fc6_response :: proc(
	request_header: modbus.ModbusHeader,
	function_code: u8,
	address: u16,
	value: u16,
	response_frame: []u8,
) -> int {
	mbap_length: u16 = 2 + 4
	framewriter_write_header(request_header, mbap_length, response_frame)

	response_frame[modbus.FUNCTION_CODE_OFFSET_IN_FRAME] = function_code
	endian.put_u16(response_frame[8:10], .Big, address)
	endian.put_u16(response_frame[10:12], .Big, value)

	return modbus.MBAP_HEADER_SIZE_WITHOUT_UNIT_ID + int(mbap_length)
}

tcp_connection_close :: proc(connection: ^TcpConnection) {
	if (connection.state != .Closed) {
		net.close(connection.socket)
		connection.state = .Closed
		connection.buffer = {}
		connection.buffer_length = 0
	}
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

	dummy_server: Datapoints = {
		holding_registers = {},
	}

	for index in 0 ..< len(dummy_server.holding_registers) {
		if index % 2 == 0 {
			dummy_server.holding_registers[index] = u16(index << 8)
		} else {
			dummy_server.holding_registers[index] = u16(index)
		}
	}

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
			frame_size, next_state := handle_connection(&connection, request_frame[:])
			if next_state == .Aborted || next_state == .Closed {
				log.infof("Closing connection")
				tcp_connection_close(&connection)
				continue
			}

			parsed_header, header_error := modbus.parse_mbap_header(request_frame[:frame_size])

			if header_error != .None {
				log.info("Modbus Message format incorrect, closing connection")
				tcp_connection_close(&connection)
				continue
			}


			parsed_modbus_request, parser_error := modbus.parse_request_frame(
				parsed_header,
				request_frame[:frame_size],
			)

			if parser_error == .MessageTooShort {
				log.info("Modbus Message format incorrect, closing connection")
				tcp_connection_close(&connection)
				continue
			}


			frame: [260]u8
			if parser_error != .None {
				frame_size := framewriter_generate_exception(
					parsed_header,
					parsed_modbus_request.function_code,
					modbus.modbus_parser_error_to_exception(parser_error),
					frame[:],
				)

				if !tcp_send_modbus_frame(frame[:frame_size], &connection) {
					log.error("cannot send frame to client")
					tcp_connection_close(&connection)
				}

				continue
			}

			//TODO: We need a function code dispatcher to handle all possible payloads
			//as of right now we only have fc3, so there is only one thing we need to handle

			response_register_value_buffer: [125]u16

			switch payload in parsed_modbus_request.args {
			case modbus.ModbusReadHoldingRegister:
				exception := fc_read_holding_registers_handler(
					&dummy_server,
					payload.start_address,
					payload.quantity,
					response_register_value_buffer[:int(payload.quantity)],
				)

				if exception != .None {
					frame_size := framewriter_generate_exception(
						parsed_modbus_request.header,
						parsed_modbus_request.function_code,
						exception,
						frame[:],
					)

					tcp_send_modbus_frame(frame[:frame_size], &connection)
				} else {
					frame_size := framewriter_generate_fc3_response(
						parsed_modbus_request.header,
						parsed_modbus_request.function_code,
						response_register_value_buffer[:int(payload.quantity)],
						frame[:],
					)

					log.infof("Sending frame: %v", frame[:frame_size])
					tcp_send_modbus_frame(frame[:frame_size], &connection)
				}
			case modbus.ModbusWriteSingleHoldingRegisterRequest:
				exception := fc_write_single_holding_register(
					&dummy_server,
					payload.address,
					payload.value,
				)

				if exception != .None {
					frame_size := framewriter_generate_exception(
						parsed_modbus_request.header,
						parsed_modbus_request.function_code,
						exception,
						frame[:],
					)
					tcp_send_modbus_frame(frame[:frame_size], &connection)
				} else {
					frame_size := framewriter_generate_fc6_response(
						parsed_modbus_request.header,
						parsed_modbus_request.function_code,
						payload.address,
						payload.value,
						frame[:],
					)

					log.infof("Sending frame: %v", frame[:frame_size])
					tcp_send_modbus_frame(frame[:frame_size], &connection)
				}

			}

			log.infof("request: %v", parsed_modbus_request)
		}
	}
}
