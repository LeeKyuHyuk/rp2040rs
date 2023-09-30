mod intelhex;
mod rp2040;

use rp2040::*;

fn main() {
    let mut mcu = initialize("./examples/blink.hex");
    mcu.registers[PC] = 0x370;
    for _index in 0..60 {
        execute_instruction(&mut mcu);
    }
}
