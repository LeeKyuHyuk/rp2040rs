use crate::rp2040::RP2040;

pub const UART0_BASE:u32 = 0x40034000;
pub const UART1_BASE:u32 = 0x40038000;

const UARTDR:u32 = 0x0;
const UARTFR:u32 = 0x18;

pub fn rp2040_uart(rp2040: &mut RP2040, base_address: u32, on_byte: fn(address: u32, value: u32)) {
    rp2040.write_hooks.insert(base_address + UARTDR, on_byte);
    rp2040.read_hooks.insert(UART0_BASE + UARTFR, |_| 0);
}