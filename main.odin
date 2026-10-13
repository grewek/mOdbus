package main

import "core:encoding/endian"
import "core:log"
import "core:net"
import "core:os"
import "core:testing"
import "core:thread"

MBAP_Header :: struct {
	transaction_id: u16,
	protocol_id:    u16,
	length:         u16,
	unit_id:        u8,
}

parse_mbap_header :: proc(message: []u8) -> (MBAP_Header, bool) {

	if len(message) < size_of(MBAP_Header) {
		log.errorf("Expected a length of %v but got %v", size_of(MBAP_Header), message)
		return {}, false
	}

	transaction_id, transaction_ok := endian.get_u16(message[0:2], .Big)
	if !transaction_ok {
		log.errorf("cannot read transaction id from message")
		return {}, false
	}

	protocol_id, protocol_ok := endian.get_u16(message[2:4], .Big)
	if !protocol_ok {
		log.errorf("cannot read protocol id from message")
		return {}, false
	}

	if protocol_id != 0 {
		log.errorf("invalid protocol id indicated by the header")
		return {}, false
	}

	length, length_ok := endian.get_u16(message[4:6], .Big)
	if !length_ok {
		log.errorf("cannot read length from message")
		return {}, false
	}

	if length > 253 {
		log.errorf("length field has an invalid size")
		return {}, false
	}

	return MBAP_Header {
			transaction_id = transaction_id,
			protocol_id = protocol_id,
			length = length,
			unit_id = message[6],
		},
		true
}

handle_message :: proc(header: MBAP_Header, message: []u8) {
	log.infof("Header Info: %v", header)
}

RingBuffer :: struct {
	data:           [512]u8,
	filled:         bool,
	read_position:  int,
	write_position: int,
}

ring_buffer_length :: proc(ring_buffer: ^RingBuffer) -> int {
	assert(ring_buffer.write_position >= 0 && ring_buffer.write_position < 512)
	assert(ring_buffer.read_position >= 0 && ring_buffer.read_position < 512)

	if ring_buffer.filled {
		return len(ring_buffer.data)
	}

	return ((ring_buffer.write_position - ring_buffer.read_position) + 512) % 512
}

@(test)
test_ring_buffer_length :: proc(t: ^testing.T) {
	buffer := RingBuffer {
		filled         = false,
		read_position  = 0,
		write_position = 0,
	}

	testing.expect_value(t, ring_buffer_length(&buffer), 0)

	buffer.read_position = 0
	buffer.write_position = 1
	testing.expect_value(t, ring_buffer_length(&buffer), 1)

	buffer.read_position = 0
	buffer.write_position = 2
	testing.expect_value(t, ring_buffer_length(&buffer), 2)

	buffer.read_position = 10
	buffer.write_position = 511
	testing.expect_value(t, ring_buffer_length(&buffer), 501)

	buffer.read_position = 500
	buffer.write_position = 10
	testing.expect_value(t, ring_buffer_length(&buffer), 22)

	buffer.filled = true
	buffer.read_position = 128
	buffer.write_position = 128
	testing.expect_value(t, ring_buffer_length(&buffer), 512)

	buffer.filled = false
	buffer.read_position = 128
	buffer.write_position = 128
	testing.expect_value(t, ring_buffer_length(&buffer), 0)
}

RingBufferError :: enum {
	None,
	InsufficientSpace,
}

ring_buffer_write :: proc(ring_buffer: ^RingBuffer, data: []u8) -> RingBufferError {

	if len(data) == 0 {
		return .None
	}

	if ring_buffer.filled {
		return .InsufficientSpace
	}
	available_slots := 512 - ring_buffer_length(ring_buffer)
	if available_slots < len(data) {
		return .InsufficientSpace
	}

	for value in data {
		ring_buffer.data[ring_buffer.write_position] = value
		ring_buffer.write_position += 1


		if ring_buffer.write_position >= 512 {
			ring_buffer.write_position = 0
		}
	}

	if ring_buffer.write_position == ring_buffer.read_position {
		ring_buffer.filled = true
	}

	return .None
}

@(test)
test_ring_buffer_writes_correctly :: proc(t: ^testing.T) {
	buffer := RingBuffer {
		filled         = false,
		read_position  = 0,
		write_position = 0,
	}

	data_slice_empty := []u8{}

	result_a := ring_buffer_write(&buffer, data_slice_empty[:])

	testing.expect_value(t, result_a, .None)
	testing.expect_value(t, buffer.write_position, 0)

	data_slice_one := []u8{0x01, 0x02, 0x03, 0x04}

	result_b := ring_buffer_write(&buffer, data_slice_one[:])

	testing.expect_value(t, result_b, .None)
	testing.expect_value(t, buffer.data[0], 1)
	testing.expect_value(t, buffer.data[1], 2)
	testing.expect_value(t, buffer.data[2], 3)
	testing.expect_value(t, buffer.data[3], 4)
	testing.expect_value(t, buffer.write_position, 4)

	data_slice_two := []u8{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}

	result_c := ring_buffer_write(&buffer, data_slice_two[:])

	testing.expect_value(t, result_c, .None)
	testing.expect_value(t, buffer.data[4], 5)
	testing.expect_value(t, buffer.data[5], 6)
	testing.expect_value(t, buffer.data[6], 7)
	testing.expect_value(t, buffer.data[7], 8)
	testing.expect_value(t, buffer.data[8], 9)
	testing.expect_value(t, buffer.data[9], 10)
	testing.expect_value(t, buffer.write_position, 10)

	buffer.read_position = 2
	buffer.write_position = 510

	result_d := ring_buffer_write(&buffer, data_slice_two[:])

	testing.expect_value(t, result_d, .InsufficientSpace)

	buffer.filled = true
	buffer.write_position = 20
	buffer.read_position = 20

	result_e := ring_buffer_write(&buffer, data_slice_two[:])
	testing.expect_value(t, result_e, .InsufficientSpace)

	buffer.filled = false
	buffer.write_position = 0
	buffer.read_position = 0


	data := [512]u8{}
	for value, idx in 0 ..< 512 {
		data[idx] = u8(value)
	}

	result_f := ring_buffer_write(&buffer, data[:])
	testing.expect_value(t, result_f, .None)

}

ring_buffer_read :: proc(ring_buffer: ^RingBuffer) -> []u8 {
	return ring_buffer.data[:]
}

handle_connection :: proc(connection: net.TCP_Socket) {
	message_buffer: [512]u8
	total_received := 0

	for {
		bytes_received, err_received := net.recv_tcp(connection, message_buffer[:])

		if err_received != nil {
			log.errorf("failed to receive data: %v", err_received)
		}

		received := message_buffer[:bytes_received]
		total_received += bytes_received

		if len(received) == 0 {
			log.infof("client disconnected")
			break
		}

		header, ok := parse_mbap_header(received)

		if !ok {
			log.error("Client send invalid header closing connection")
			break
		}

		handle_message(header, message_buffer[:7])


		log.infof("Server received [%d bytes]: %v", bytes_received, received)
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

	log.infof("Server listening on \"%v:%v\"", address, port)

	for {
		incoming_connection, from, err_accept := net.accept_tcp(sock)
		if err_accept != nil {
			log.errorf("connection refused reason: %v", err_accept)
			continue
		} else {
			log.info("Connection accepted")
		}

		thread.create_and_start_with_poly_data(incoming_connection, handle_connection, context)
	}

	defer net.close(sock)
}
