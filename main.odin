package main

import "core:encoding/endian"
import "core:log"
import "core:net"
import "core:os"
import "core:time"

//data offsets in request payloads and size of data if the data is one byte in size there is only an address

TRANSACTION_ID_OFFSET_IN_FRAME :: 0
TRANSACTION_ID_SIZE_IN_FRAME :: 2

PROTOCOL_ID_OFFSET_IN_FRAME :: 2
PROTOCOL_ID_SIZE_IN_FRAME :: 2

LENGTH_FIELD_OFFSET_IN_FRAME :: 4
LENGTH_FIELD_SIZE_IN_FRAME :: 2

UNIT_ID_OFFSET_IN_FRAME :: 6
FUNCTION_CODE_OFFSET_IN_FRAME :: 7

ADDRESS_FIELD_OFFSET_IN_FRAME :: 8
ADDRESS_FIELD_SIZE_IN_FRAME :: 2

EXCEPTION_FIELD_OFFSET_IN_FRAME :: 8

QUANTITY_FIELD_OFFSET_IN_FRAME :: 10
QUANTITY_FIELD_SIZE_IN_FRAME :: 2

//length of modbus response payloads with a known static size
MODBUS_EXCEPTION_FRAME_PAYLOAD_LENGTH :: 3

//constants for known minimum and maximum values inside a message
MODBUS_HOLDING_REGISTERS_MINIMUM_QUANTITY :: 1
MODBUS_HOLDING_REGISTERS_MAXIMUM_QUANTITY :: 125

//constants for known request messages sizes that need to be at least n bytes long
MINIMUM_FRAME_LENGTH_FC3_REQUEST :: 12


//constants for known function codes
FUNCTION_CODE_READ_HOLDING_REGISTERS :: 3

//constants for necessary header values
MBAP_HEADER_SIZE :: 7

MODBUS_PROTOCOL_ID :: 0

MINIMUM_HEADER_LENGTH :: 2
MAXIMUM_HEADER_LENGTH :: 254


MODBUS_TCP_MAX_FRAME_SIZE :: 260

ModbusHeader :: struct {
	transaction_id: u16,
	protocol_id:    u16,
	length:         u16,
	unit_id:        u8,
}

FrameError :: enum {
	None,
	InsufficientLength,
	InvalidProtocolId,
	InvalidLength,
}

ModbusRequestMessage :: struct {
	header:        ModbusHeader,
	function_code: u8,
	args:          ModbusRequestPayload,
	// ...
}

ModbusResponseMessage :: struct {
	header:        ModbusHeader,
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

ModbusParserErrorMetadata :: struct {
	header:        ModbusHeader,
	function_code: u8,
	parser_error:  ModbusParserError,
}

ModbusParserOperationResult :: union {
	ModbusRequestMessage,
	ModbusParserErrorMetadata,
}

parse_mbap_header :: proc(message: []u8) -> (ModbusHeader, FrameError) {

	if len(message) < MBAP_HEADER_SIZE {
		log.errorf("Expected a length of %v but got %v", MBAP_HEADER_SIZE, len(message))
		return {}, .InsufficientLength
	}

	transaction_id, _ := endian.get_u16(
		message[TRANSACTION_ID_OFFSET_IN_FRAME:(TRANSACTION_ID_OFFSET_IN_FRAME +
			TRANSACTION_ID_SIZE_IN_FRAME)],
		.Big,
	)
	protocol_id, _ := endian.get_u16(
		message[PROTOCOL_ID_OFFSET_IN_FRAME:(PROTOCOL_ID_OFFSET_IN_FRAME +
			PROTOCOL_ID_SIZE_IN_FRAME)],
		.Big,
	)
	length, _ := endian.get_u16(
		message[LENGTH_FIELD_OFFSET_IN_FRAME:(LENGTH_FIELD_OFFSET_IN_FRAME +
			LENGTH_FIELD_SIZE_IN_FRAME)],
		.Big,
	)

	if protocol_id != MODBUS_PROTOCOL_ID {
		log.errorf("invalid protocol id indicated by the header")
		return {}, .InvalidProtocolId
	}

	if length < MINIMUM_HEADER_LENGTH || length > MAXIMUM_HEADER_LENGTH {
		log.errorf("length field has an invalid size")
		return {}, .InvalidLength
	}

	return ModbusHeader {
			transaction_id = transaction_id,
			protocol_id = protocol_id,
			length = length,
			unit_id = message[UNIT_ID_OFFSET_IN_FRAME],
		},
		.None
}


modbus_parser_error_to_exception :: proc(parser_error: ModbusParserError) -> ModbusExceptionCode {
	switch parser_error {
	case .None:
		fallthrough
	case .MessageTooShort:
		unreachable()
	case .UnknownFunctionCode:
		return .IllegalFunction
	case .IllegalDataAddress:
		return .IllegalDataAddress
	case .IllegalDataValue:
		return .IllegalDataValue
	case:
		unreachable()
	}
}
modbus_parse_payload :: proc(header: ModbusHeader, message: []u8) -> ModbusParserOperationResult {
	fc := message[FUNCTION_CODE_OFFSET_IN_FRAME]
	switch fc {
	case FUNCTION_CODE_READ_HOLDING_REGISTERS:
		{
			if len(message) < MINIMUM_FRAME_LENGTH_FC3_REQUEST {
				log.info("Insufficient Bytes received to parse FC3")
				return ModbusParserErrorMetadata {
					header = header,
					function_code = fc,
					parser_error = .MessageTooShort,
				}
			}

			raw_address := message[ADDRESS_FIELD_OFFSET_IN_FRAME:(ADDRESS_FIELD_OFFSET_IN_FRAME +
				ADDRESS_FIELD_SIZE_IN_FRAME)]
			start_address, _ := endian.get_u16(raw_address, .Big)

			raw_quantity := message[QUANTITY_FIELD_OFFSET_IN_FRAME:(QUANTITY_FIELD_OFFSET_IN_FRAME +
				QUANTITY_FIELD_SIZE_IN_FRAME)]
			quantity, _ := endian.get_u16(raw_quantity, .Big)

			//NOTE: According to the specification, the server can
			// throw an exception if the address value is out of range
			// but in reality the range is 0x0000 to 0xFFFF which can
			// never happen in the first place. The quantity however still
			// needs to be checked to be less than or equal 0x7D.
			if quantity < MODBUS_HOLDING_REGISTERS_MINIMUM_QUANTITY ||
			   quantity > MODBUS_HOLDING_REGISTERS_MAXIMUM_QUANTITY {
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
		return ModbusParserErrorMetadata {
			header = header,
			function_code = fc,
			parser_error = .UnknownFunctionCode,
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

	response.header.length = MODBUS_EXCEPTION_FRAME_PAYLOAD_LENGTH
	return response
}


handle_message :: proc(message: []u8) -> (ModbusResponseMessage, ModbusParserError) {
	log.debugf("Raw Message: %v", message[:])

	//NOTE: All fields of the header contained in the frame were already
	//      checked when the message was received so we don't need to check
	//      that again.
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
	// A Frame that is received by a TCP Socket can only contain a maximum
	// of 260 bytes, which means that this buffer can house one frame in
	// the worst case.
	// NOTE: __check__ that if we use async or threads later
	// there is no way for the user to write data behind the buffer.
	buffer:        [512]u8,
	buffer_length: int,
}

modbus_payload_to_frame_buffer :: proc(modbus_payload: ModbusResponsePayload, frame_buffer: []u8) {
	switch payload in modbus_payload {
	case ModbusException:
		frame_buffer[EXCEPTION_FIELD_OFFSET_IN_FRAME] = payload.exception_code
	}
}

modbus_response_to_frame_buffer :: proc(
	response: ModbusResponseMessage,
	frame_buffer: []u8,
) -> int {
	if len(frame_buffer) < int(response.header.length) + MBAP_HEADER_SIZE {
		log.infof("cannot convert message into frame, buffer length too small")
		return -1
	}

	if ok := endian.put_u16(
		frame_buffer[TRANSACTION_ID_OFFSET_IN_FRAME:],
		.Big,
		response.header.transaction_id,
	); !ok {
		log.info("cannot write transaction id into response frame")
		return -1
	}
	if ok := endian.put_u16(
		frame_buffer[PROTOCOL_ID_OFFSET_IN_FRAME:],
		.Big,
		response.header.protocol_id,
	); !ok {
		log.info("cannot write protocol id into response frame")
		return -1
	}
	if ok := endian.put_u16(
		frame_buffer[LENGTH_FIELD_OFFSET_IN_FRAME:],
		.Big,
		response.header.length,
	); !ok {
		log.info("cannot write length into response frame")
		return -1
	}

	frame_buffer[UNIT_ID_OFFSET_IN_FRAME] = response.header.unit_id
	frame_buffer[FUNCTION_CODE_OFFSET_IN_FRAME] = response.function_code

	modbus_payload_to_frame_buffer(response.args, frame_buffer)

	//TODO: For now we assume that we have written the complete frame
	return int(response.header.length) + (MBAP_HEADER_SIZE - 1)
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

				if err == .MessageTooShort {
					log.info("frame is too short parser refused to consume message")
					return
				}

				response_frame_buffer := [MODBUS_TCP_MAX_FRAME_SIZE]u8{}
				response_frame_size := modbus_response_to_frame_buffer(
					response,
					response_frame_buffer[:],
				)

				if response_frame_size == -1 {
					log.error("response could not be built due to errors closing connection")
					return
				}

				byte_send_count: int = 0
				for byte_send_count < response_frame_size {
					bytes_send, send_error := net.send_tcp(
						connection.socket,
						response_frame_buffer[byte_send_count:response_frame_size],
					)
					if send_error != .None {
						log.error("cannot send data disconnecting client")
						return
					}

					if bytes_send == 0 {
						log.error("could not send data, disconnecting client")
						return
					}


					byte_send_count += bytes_send
				}


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

		if err_accept != .None {
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

		handle_connection(&connection)
		net.close(incoming_connection)
	}
}
