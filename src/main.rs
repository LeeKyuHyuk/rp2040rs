mod assembler;
mod intelhex;
mod rp2040;
mod uart;

use std::char::from_u32;

use rp2040::*;
use uart::*;

fn main() {
    let mut mcu = initialize("./examples/hello_uart.hex");

    let on_byte: fn(address: u32, value: u32) = |_address, value| {
        println!(
            "UART sent : {}",
            from_u32(value & 0xFF)
                .expect("There is a problem converting ASCII codes to characters")
        );
    };
    rp2040_uart(&mut mcu, UART0_BASE, on_byte);

    mcu.registers[PC] = 0x10000370;
    for _index in 0..280 {
        execute_instruction(&mut mcu);
        // uncomment for debugging:
        // println!("{:#08x} , {:#08x}", mcu.registers[PC], mcu.registers[2]);
    }
}
