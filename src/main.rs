mod intelhex;
mod rp2040;

use rp2040::*;

fn main() {
    let mut mcu = initialize("./examples/hello_uart.hex");

    mcu.read_hooks.insert(0x40034018, |_| 0);

    mcu.registers[PC] = 0x370;
    for _index in 0..60 {
        execute_instruction(&mut mcu);
        println!("{:#08x}", mcu.registers[PC]);
    }
}
