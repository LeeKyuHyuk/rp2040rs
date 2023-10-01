mod assembler;
mod intelhex;
mod rp2040;

use std::char::from_u32;

use rp2040::*;

const UART0_BASE: u32 = 0x40034000;
const UARTDR: u32 = 0x0;
const UARTFR: u32 = 0x18;

fn main() {
    let mut mcu = initialize("./examples/hello_uart.hex");

    mcu.write_hooks
        .insert(UART0_BASE + UARTDR, |_address, value| {
            println!(
                "UART sent : {}",
                from_u32(value & 0xFF)
                    .expect("There is a problem converting ASCII codes to characters")
            );
        });
    mcu.read_hooks.insert(UART0_BASE + UARTFR, |_| 0);

    mcu.registers[PC] = 0x370;
    for _index in 0..280 {
        execute_instruction(&mut mcu);
        // uncomment for debugging:
        // println!("{:#08x} , {:#08x}", mcu.registers[PC], mcu.registers[2]);
    }
}
