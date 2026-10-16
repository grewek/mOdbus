package main

import "core:encoding/endian"
import "core:log"
import "core:net"
import "core:os"
import "core:time"

MBAP_Header :: struct {
	transaction_id: u16,
	protocol_id:    u16,
	length:         u16,
	unit_id:        u8,
}

MBAP_ParserError :: enum {
	None,
	InsufficientLength,
	InvalidProtocolId,
	InvalidLength,
}

parse_mbap_header :: proc(message: []u8) -> (MBAP_Header, MBAP_ParserError) {

	if len(message) < MBAP_HEADER_SIZE {
		log.errorf("Expected a length of %v but got %v", MBAP_HEADER_SIZE, len(message))
		return {}, .InsufficientLength
	}

	transaction_id, _ := endian.get_u16(message[0:2], .Big)
	protocol_id, _ := endian.get_u16(message[2:4], .Big)
	length, _ := endian.get_u16(message[4:6], .Big)

	if protocol_id != 0 {
		log.errorf("invalid protocol id indicated by the header")
		return {}, .InvalidProtocolId
	}

	if length < 2 || length > 254 {
		log.errorf("length field has an invalid size")
		return {}, .InvalidLength
	}

	return MBAP_Header {
			transaction_id = transaction_id,
			protocol_id = protocol_id,
			length = length,
			unit_id = message[6],
		},
		.None
}

ModbusRequestMessage :: struct {
	header:        MBAP_Header,
	function_code: u8,
	args:          ModbusRequestPayload,
	// ...
}

ModbusResponseMessage :: struct {
	header:        MBAP_Header,
	function_code: u8,
	args:          ModbusResponsePayload,
}

ReadHoldingRegister :: struct {
	start_address: u16,
	quantity:      u16,
}

ModbusRequestPayload :: union {
	ReadHoldingRegister,
}

ModbusResponsePayload :: union {
	ModbusException,
}

ModbusException :: struct {
	exception_code: u8,
}

ModbusParserError :: enum {
	None = 0x00,
	UnknownFunctionCode,
	IllegalDataAddress,
	IllegalDataValue,
	MessageTooShort,
}

ModbusExceptionCode :: enum {
	IllegalFunction        = 0x01,
	IllegalDataAddress     = 0x02,
	IllegalDataValue       = 0x03,
	DeviceFailure          = 0x04,
	Acknowledged           = 0x05,
	DeviceBusy             = 0x06,
	ParityError            = 0x08,
	GatewayUnavailable     = 0x0A,
	GatewayFailedToRespond = 0x0B,
}

FUNCTION_CODE_READ_HOLDING_REGISTERS :: 3

ModbusParserErrorMetadata :: struct {
	header:        MBAP_Header,
	function_code: u8,
	parser_error:  ModbusParserError,
}

ModbusParserOperationResult :: union {
	ModbusRequestMessage,
	ModbusParserErrorMetadata,
}

FUNCTION_CODE_OFFSET_IN_MESSAGE :: 7

ADDRESS_FIELD_OFFSET_IN_MESSAGE :: 8
ADDRESS_FIELD_SIZE_IN_MESSAGE :: 2

QUANTITY_FIELD_OFFSET_IN_MESSAGE :: 10
QUANTITY_FIELD_SIZE_IN_MESSAGE :: 2

modbus_parser_error_to_exception :: proc(parser_error: ModbusParserError) -> ModbusExceptionCode {
	switch parser_error {
	case .None:
		assert(false, "unreachable code reached")
	case .MessageTooShort:
		assert(false, "unreachable code reached")
	case .UnknownFunctionCode:
		return .IllegalFunction
	case .IllegalDataAddress:
		return .IllegalDataAddress
	case .IllegalDataValue:
		return .IllegalDataValue
	case:
		assert(
			false,
			"unreachable code reached due to calling the function with values that can't be converted into an exception",
		)
	}

	return nil
}
modbus_parse_payload :: proc(header: MBAP_Header, message: []u8) -> ModbusParserOperationResult {
	fc := message[FUNCTION_CODE_OFFSET_IN_MESSAGE]
	switch fc {
	case FUNCTION_CODE_READ_HOLDING_REGISTERS:
		{
			if len(message) < 12 {
				log.info("Insufficient Bytes received to parse FC3")
				return ModbusParserErrorMetadata {
					header = header,
					function_code = fc,
					parser_error = .MessageTooShort,
				}
			}

			raw_address := message[ADDRESS_FIELD_OFFSET_IN_MESSAGE:(ADDRESS_FIELD_OFFSET_IN_MESSAGE +
				ADDRESS_FIELD_SIZE_IN_MESSAGE)]
			start_address, _ := endian.get_u16(raw_address, .Big)

			raw_quantity := message[QUANTITY_FIELD_OFFSET_IN_MESSAGE:(QUANTITY_FIELD_OFFSET_IN_MESSAGE +
				QUANTITY_FIELD_SIZE_IN_MESSAGE)]
			quantity, _ := endian.get_u16(raw_quantity, .Big)

			//NOTE: According to the specification, the server can
			// throw an exeception if the address value is out of range
			// but in reality the range is 0x0000 to 0xFFFF which can
			// never happen in the first place. The quantity however still
			// needs to be checked to be less than or equal 0x7D.
			if quantity == 0 || quantity > 0x7D {
				return ModbusParserErrorMetadata {
					header = header,
					function_code = fc,
					parser_error = .IllegalDataValue,
				}
			}

			return ModbusRequestMessage {
				header = header,
				function_code = fc,
				args = ReadHoldingRegister{start_address = start_address, quantity = quantity},
			}
		}
	case:
		{
			return ModbusParserErrorMetadata {
				header = header,
				function_code = fc,
				parser_error = .UnknownFunctionCode,
			}
		}
	}
}

modbus_generate_exception_answer :: proc(
	request: ModbusParserErrorMetadata,
) -> ModbusResponseMessage {

	exception_value := modbus_parser_error_to_exception(request.parser_error)
	response := ModbusResponseMessage {
		header = request.header,
		function_code = request.function_code | 0x80,
		args = ModbusException{exception_code = u8(exception_value)},
	}

	return response
}


handle_message :: proc(message: []u8) -> (ModbusResponseMessage, ModbusParserError) {
	log.debugf("Raw Message: %v", message[:])

	header, _ := parse_mbap_header(message)
	log.infof("Header of Received Message: %v", header)

	payload_result := modbus_parse_payload(header, message)

	switch result in payload_result {
	case ModbusRequestMessage:
		log.infof("Payload: %v", result)
		assert(false, "TODO: Handle the success case")
	case ModbusParserErrorMetadata:
		if result.parser_error == .MessageTooShort {
			return {}, result.parser_error
		} else {
			return modbus_generate_exception_answer(result), .None
		}
	}

	return {}, .None
}

MBAP_HEADER_SIZE :: 7

MessageState :: enum {
	Validated,
	Incomplete,
	Invalid,
}

validate_message :: proc(raw_message: []u8) -> (int, MessageState) {
	if len(raw_message) < MBAP_HEADER_SIZE {
		return -1, .Incomplete
	}

	header, header_valid := parse_mbap_header(raw_message[:MBAP_HEADER_SIZE])

	if header_valid != .None {
		return -1, .Invalid
	}

	frame_size := (MBAP_HEADER_SIZE - 1) + int(header.length)
	if len(raw_message) < frame_size {
		return -1, .Incomplete
	}


	return frame_size, .Validated
}

TcpConnection :: struct {
	socket:        net.TCP_Socket,
	timeout:       time.Duration,
	buffer:        [512]u8,
	buffer_length: int,
}

modbus_response_to_frame_buffer :: proc(
	response: ModbusResponseMessage,
	frame_buffer: []u8,
) -> int {
	if len(frame_buffer) < int(response.header.length) + MBAP_HEADER_SIZE {
		log.infof("cannot convert message into frame, buffer length too small")
	}

	transaction_id_bytes := []u8 {
		u8(response.header.transaction_id & u16(0x00FF)),
		u8((response.header.transaction_id >> 16) & 0x00FF),
	}

	protocol_id_bytes := []u8 {
		u8(response.header.protocol_id & u16(0x00FF)),
		u8((response.header.protocol_id >> 16) & 0x00FF),
	}

	length_bytes := []u8 {
		u8(response.header.length & u16(0x00FF)),
		u8((response.header.length >> 16) & 0x00FF),
	}

	copy(frame_buffer[0:], transaction_id_bytes[0:])
	copy(frame_buffer[2:], protocol_id_bytes[0:])
	copy(frame_buffer[4:], length_bytes[0:])

	frame_buffer[5] = response.header.unit_id
	frame_buffer[6] = response.function_code

	//TODO: Marshal the Payload into the frame_buffer

	//TODO: For now we assume that we have written the complete frame
	return int(response.header.length) + MBAP_HEADER_SIZE
}

handle_connection :: proc(connection: ^TcpConnection) {
	//TODO: The timeout is for recv_tcp it does not measure the time it takes to get the whole frame. This is something i should take into consideration
	sock_option_error := net.set_option(connection.socket, .Receive_Timeout, connection.timeout)

	if sock_option_error != .None {
		log.errorf(
			"Error occurred while setting timeout for socket cannot continue: %v",
			sock_option_error,
		)
		return
	}

	for {
		bytes_received, err_received := net.recv_tcp(
			connection.socket,
			connection.buffer[connection.buffer_length:],
		)
		connection.buffer_length += bytes_received

		log.infof("Received data with length of %v", connection.buffer_length)
		if err_received != .None {
			log.errorf("failed to receive data: %v", err_received)
			break
		}

		if bytes_received == 0 {
			log.info("client closed connection")
			break
		}

		for {
			frame_size, frame_valid := validate_message(
				connection.buffer[0:connection.buffer_length],
			)

			if frame_valid == .Incomplete {
				break
			}

			if frame_valid == .Invalid {
				log.info("Received invalid frame, server is closing connection")
				return
			}

			if frame_valid == .Validated {
				log.infof(
					"Server received [%d bytes]: %v",
					frame_size,
					connection.buffer[:frame_size],
				)
				response, err := handle_message(connection.buffer[:frame_size])

				response_frame_buffer := [260]u8{}
				frame_size := modbus_response_to_frame_buffer(response, response_frame_buffer[:])

				net.send_tcp(connection.socket, response_frame_buffer[frame_size:])
				copy_slice(
					connection.buffer[0:],
					connection.buffer[frame_size:connection.buffer_length],
				)
				connection.buffer_length -= frame_size
			}
		}
	}
}

CONNECTION_TIMEOUT_IN_SECS :: 5

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

	for {
		incoming_connection, from, err_accept := net.accept_tcp(sock)

		if err_accept != nil {
			log.errorf("connection refused reason: %v", err_accept)
			continue
		} else {
			log.infof("Connection accepted: %v", from.address)
		}


		connection := TcpConnection {
			socket        = incoming_connection,
			timeout       = time.Second * CONNECTION_TIMEOUT_IN_SECS,
			buffer        = {},
			buffer_length = 0,
		}

		defer net.close(incoming_connection)
		handle_connection(&connection)
	}
}
