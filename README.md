# mOdbus

mOdbus is a implementation of a Modbus server in odin. It is loosely based on infused_modbus which will in the long run be replaced by this
reimplementaton.

## Components

The Project is splitted into three parts: 
- a protocol-core which contains the necessary modbus message data structures and their encoding/decoding routines.
- a connection layer which determines how the connection is established either via TCP/RTU or TLS

These components are then integrated into a modbus server and client application where one can chosse which layer to use and
what function codes to activate.

## Server

The Server is 100% Modbus compatible and integrates all function codes that are described by the standard the only additional
feature that the server contains is the ability to describe it's data layout to the client with the help of the `device_description.toml`
file. This ability is provided by the use of `fc43 (Read Device Identification) and fc20 (Read File)` which does not break the compatibility
with different modbus servers like libmodbus.

## Client

The client is also 100% Modbus compatible, it only advantage is that it knows how to read and interpret the `device_description.toml` provided
by the server.

## device_description

A modbus device description provides the server the ability to describe it's core data attributes to the client, so that the client can provide
the layout of the device to the user so the user can make a more informed decisions.

Here is an example for a device_description:

``` toml
[my_machine]
unit_id = 1

[my_machine.hr_settings]
endianness = ABCD
base_address = 40000

[my_machine.hr_registers.entries]
offset = 1 
data_type = i32

[my_machine.ir_registers]
base_address = 
```

__NOTE__: The description format isn't complete, this is a first draft.
