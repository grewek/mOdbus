package modbus

import "core:encoding/endian"
import "core:log"

PDU_PROLOG_SIZE :: 2


TRANSACTION_ID_OFFSET_IN_FRAME :: 0
TRANSACTION_ID_SIZE_IN_FRAME :: 2

PROTOCOL_ID_OFFSET_IN_FRAME :: 2
PROTOCOL_ID_SIZE_IN_FRAME :: 2

LENGTH_FIELD_OFFSET_IN_FRAME :: 4
LENGTH_FIELD_SIZE_IN_FRAME :: 2

LENGTH_FIELD_OFFSET_FC3_RESPONSE :: 8

UNIT_ID_OFFSET_IN_FRAME :: 6
UNIT_ID_SIZE_IN_FRAME :: 1

FUNCTION_CODE_OFFSET_IN_FRAME :: 7
FUNCTION_CODE_SIZE_IN_FRAME :: 1

ADDRESS_FIELD_OFFSET_IN_FRAME :: 8
ADDRESS_FIELD_SIZE_IN_FRAME :: 2

EXCEPTION_FIELD_OFFSET_IN_FRAME :: 8

QUANTITY_FIELD_OFFSET_IN_FRAME :: 10
QUANTITY_FIELD_SIZE_IN_FRAME :: 2

BYTE_FIELD_OFFSET_IN_FC3_RESPONSE_FRAME :: 8
BYTE_COUNT_FIELD_SIZE :: 1

VALUE_FIELD_OFFSET_IN_FRAME :: 10
VALUE_FIELD_SIZE_IN_FRAME :: 2

//length of modbus response payloads with a known static size
MODBUS_EXCEPTION_FRAME_PAYLOAD_LENGTH :: 3
MODBUS_PDU_RESPONSE_LENGTH_FC6 :: 4

//constants for known minimum and maximum values inside a message

MODBUS_COILS_MINIMUM_QUANTITY :: 1
MODBUS_COILS_MAXIMUM_QUANTITY :: 2000

MODBUS_HOLDING_REGISTERS_MINIMUM_QUANTITY :: 1
MODBUS_HOLDING_REGISTERS_MAXIMUM_QUANTITY :: 125

//TODO(Kay): Let's define a individual Frame length for each Request for now. Later on we should extract this into a singular
//           constant where possible.
//constants for known request messages sizes that need to be at least n bytes long
MINIMUM_FRAME_LENGTH_FC1_REQUEST :: 12
MINIMUM_FRAME_LENGTH_FC3_REQUEST :: 12
MINIMUM_FRAME_LENGTH_FC6_REQUEST :: 12

//constants for known function codes
FUNCTION_CODE_READ_COILS :: 1
FUNCTION_CODE_READ_HOLDING_REGISTERS :: 3
FUNCTION_CODE_WRITE_SINGLE_REGISTER :: 6

//constants for necessary header values
MBAP_HEADER_SIZE :: 7
MBAP_HEADER_SIZE_WITHOUT_UNIT_ID :: 6

MODBUS_PROTOCOL_ID :: 0

MINIMUM_HEADER_LENGTH :: 2
MAXIMUM_HEADER_LENGTH :: 254


ModbusHeader :: struct {
	transaction_id: u16,
	protocol_id:    u16,
	length:         u16,
	unit_id:        u8,
}

FrameHeaderError :: enum {
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

ModbusReadCoilsRequest :: struct {
	start_address: u16,
	quantity:      u16,
}
ModbusReadHoldingRegisterRequest :: struct {
	start_address: u16,
	quantity:      u16,
}

ModbusWriteSingleHoldingRegisterRequest :: struct {
	address: u16,
	value:   u16,
}

ModbusRequestPayload :: union {
	ModbusReadCoilsRequest,
	ModbusReadHoldingRegisterRequest,
	ModbusWriteSingleHoldingRegisterRequest,
}

ModbusResponsePayload :: union {
	ModbusException,
	ModbusReadHoldingRegisterResponse,
	ModbusWriteSingleHoldingRegisterResponse,
}

ModbusReadHoldingRegisterResponse :: struct {
	values: []u16,
}

ModbusWriteSingleHoldingRegisterResponse :: struct {
	address: u16,
	value:   u16,
}


ModbusException :: struct {
	function_code:  u8,
	exception_code: u8,
}

ModbusParserError :: enum {
	None = 0x00,
	UnknownFunctionCode,
	IllegalDataAddress,
	IllegalDataValue,
	MessageTooShort,
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

MessageState :: enum {
	Validated,
	Incomplete,
	Invalid,
}

ModbusExceptionCode :: enum {
	None                   = 0x00,
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

FrameWriterError :: enum {
	None,
	InsufficientCapacity,
	WriteFailure,
}

pack_coils :: proc(values: []bool, data_out: []u8) -> int {

	shift_position: uint = 0
	byte_index := 0

	for value in values {
		data_out[byte_index] |= (u8(value) << shift_position)
		shift_position += 1

		if shift_position == 8 {
			shift_position = 0
			byte_index += 1
		}
	}

	return byte_index
}

unpack_coils :: proc(values: []u8, data_out: []bool) -> int {
	coil_index := 0
	for value in values {
		for bit_index in 0 ..< 8 {
			data_out[coil_index] = (value >> uint(bit_index) & 0x01) == 0x01
			coil_index += 1
		}
	}

	return coil_index
}

parse_mbap_header :: proc(message: []u8) -> (ModbusHeader, FrameHeaderError) {

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

modbus_parse_fc_read_coils :: proc(
	header: ModbusHeader,
	message: []u8,
) -> ModbusParserOperationResult {
	fc := message[FUNCTION_CODE_OFFSET_IN_FRAME]
	if len(message) < MINIMUM_FRAME_LENGTH_FC1_REQUEST {
		log.info("Insufficient Bytes received to parse FC3")
		return ModbusParserErrorMetadata {
			header = header,
			function_code = fc,
			parser_error = .MessageTooShort,
		}
	}

	address_bytes := message[ADDRESS_FIELD_OFFSET_IN_FRAME:(ADDRESS_FIELD_OFFSET_IN_FRAME +
		ADDRESS_FIELD_SIZE_IN_FRAME)]
	start_address, _ := endian.get_u16(address_bytes, .Big)

	quantity_coils_bytes := message[QUANTITY_FIELD_OFFSET_IN_FRAME:(QUANTITY_FIELD_OFFSET_IN_FRAME +
		QUANTITY_FIELD_SIZE_IN_FRAME)]
	quantity, _ := endian.get_u16(quantity_coils_bytes, .Big)

	if quantity < MODBUS_COILS_MINIMUM_QUANTITY || quantity > MODBUS_COILS_MAXIMUM_QUANTITY {
		return ModbusParserErrorMetadata {
			header = header,
			function_code = fc,
			parser_error = .IllegalDataValue,
		}
	}

	return ModbusRequestMessage {
		header = header,
		function_code = fc,
		args = ModbusReadCoilsRequest{start_address = start_address, quantity = quantity},
	}
}
modbus_parse_fc_read_holding_registers :: proc(
	header: ModbusHeader,
	message: []u8,
) -> ModbusParserOperationResult {
	fc := message[FUNCTION_CODE_OFFSET_IN_FRAME]
	if len(message) < MINIMUM_FRAME_LENGTH_FC3_REQUEST {
		log.info("Insufficient Bytes received to parse FC3")
		return ModbusParserErrorMetadata {
			header = header,
			function_code = fc,
			parser_error = .MessageTooShort,
		}
	}

	address_bytes := message[ADDRESS_FIELD_OFFSET_IN_FRAME:(ADDRESS_FIELD_OFFSET_IN_FRAME +
		ADDRESS_FIELD_SIZE_IN_FRAME)]
	start_address, _ := endian.get_u16(address_bytes, .Big)

	quantity_bytes := message[QUANTITY_FIELD_OFFSET_IN_FRAME:(QUANTITY_FIELD_OFFSET_IN_FRAME +
		QUANTITY_FIELD_SIZE_IN_FRAME)]
	quantity, _ := endian.get_u16(quantity_bytes, .Big)

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
		args = ModbusReadHoldingRegisterRequest {
			start_address = start_address,
			quantity = quantity,
		},
	}
}

modbus_parse_fc_write_single_register :: proc(
	header: ModbusHeader,
	message: []u8,
) -> ModbusParserOperationResult {
	fc := message[FUNCTION_CODE_OFFSET_IN_FRAME]

	if len(message) < MINIMUM_FRAME_LENGTH_FC6_REQUEST {
		log.info("Insufficient Bytes received to parse FC3")
		return ModbusParserErrorMetadata {
			header = header,
			function_code = fc,
			parser_error = .MessageTooShort,
		}
	}

	address_bytes := message[ADDRESS_FIELD_OFFSET_IN_FRAME:(ADDRESS_FIELD_OFFSET_IN_FRAME +
		ADDRESS_FIELD_SIZE_IN_FRAME)]
	address, _ := endian.get_u16(address_bytes, .Big)

	value_bytes := message[VALUE_FIELD_OFFSET_IN_FRAME:(VALUE_FIELD_OFFSET_IN_FRAME +
		VALUE_FIELD_SIZE_IN_FRAME)]
	value, _ := endian.get_u16(value_bytes, .Big)
	return ModbusRequestMessage {
		header = header,
		function_code = fc,
		args = ModbusWriteSingleHoldingRegisterRequest{address = address, value = value},
	}
}

modbus_parse_payload :: proc(header: ModbusHeader, message: []u8) -> ModbusParserOperationResult {
	fc := message[FUNCTION_CODE_OFFSET_IN_FRAME]
	switch fc {
	case FUNCTION_CODE_READ_COILS:
		return modbus_parse_fc_read_coils(header, message)
	case FUNCTION_CODE_READ_HOLDING_REGISTERS:
		return modbus_parse_fc_read_holding_registers(header, message)
	case FUNCTION_CODE_WRITE_SINGLE_REGISTER:
		return modbus_parse_fc_write_single_register(header, message)
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

parse_request_frame :: proc(
	header: ModbusHeader,
	request_frame: []u8,
) -> (
	ModbusRequestMessage,
	ModbusParserError,
) {
	payload_result := modbus_parse_payload(header, request_frame)

	switch result in payload_result {
	case ModbusRequestMessage:
		return result, .None
	case ModbusParserErrorMetadata:
		return {}, result.parser_error
	}

	unreachable()
}


validate_frame_length :: proc(raw_message: []u8) -> bool {
	if len(raw_message) < MBAP_HEADER_SIZE {
		return false
	}

	length, _ := endian.get_u16(
		raw_message[LENGTH_FIELD_OFFSET_IN_FRAME:(LENGTH_FIELD_OFFSET_IN_FRAME +
			LENGTH_FIELD_SIZE_IN_FRAME)],
		.Big,
	)

	frame_size := (MBAP_HEADER_SIZE_WITHOUT_UNIT_ID) + int(length)
	if len(raw_message) < frame_size {
		return false
	}

	return true
}

validate_frame :: proc(raw_message: []u8) -> (int, MessageState) {
	if len(raw_message) < MBAP_HEADER_SIZE {
		return -1, .Incomplete
	}

	header, header_valid := parse_mbap_header(raw_message[:MBAP_HEADER_SIZE])

	if header_valid != .None {
		return -1, .Invalid
	}

	frame_size := (MBAP_HEADER_SIZE_WITHOUT_UNIT_ID) + int(header.length)
	if len(raw_message) < frame_size {
		return -1, .Incomplete
	}


	return frame_size, .Validated
}
