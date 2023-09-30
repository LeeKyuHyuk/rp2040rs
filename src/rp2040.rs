use std::{mem::size_of, slice::from_raw_parts_mut};

use crate::intelhex::load_hex;

const RAM_START_ADDRESS: u32 = 0x20000000;
const SIO_START_ADDRESS: u32 = 0xD0000000;

const SP: usize = 13;
const LR: usize = 14;
pub const PC: usize = 15;

pub const SRAM_SIZE: usize = 264 * 1024;
pub const FLASH_SIZE: usize = 16 * 1024 * 1024;
pub const NUMBER_OF_REGISTERS: usize = 16;

pub struct RP2040 {
    pub sram: Vec<u8>,
    pub flash: Vec<u8>,
    pub registers: [u32; NUMBER_OF_REGISTERS],
}

pub fn initialize(filename: &str) -> RP2040 {
    let mut rp2040 = RP2040 {
        sram: vec![0x00; SRAM_SIZE],
        flash: vec![0xFF; FLASH_SIZE],
        registers: [0x00; NUMBER_OF_REGISTERS],
    };
    if !filename.is_empty() {
        rp2040.registers[SP] = 0x20041000;
        rp2040.flash = load_hex(filename);
    }
    return rp2040;
}

pub fn get_flash16_ptr_mut(flash: &Vec<u8>) -> &mut [u16] {
    let length = flash.len();
    if length % size_of::<u16>() != 0 {
        panic!("The length of a flash array cannot be divided by u16");
    }
    let flash_ptr = flash.as_ptr();
    let flash16_ptr = flash_ptr as *mut u16;
    let flash16 = unsafe { from_raw_parts_mut(flash16_ptr, length / size_of::<u16>()) };
    return flash16;
}

fn write_u32(mcu: &mut RP2040, address: u32, value: u32) {
    if address >= RAM_START_ADDRESS && address < RAM_START_ADDRESS + (SRAM_SIZE as u32) {
        mcu.sram[(address - RAM_START_ADDRESS) as usize..][..4]
            .copy_from_slice(&value.to_le_bytes());
    }
    if address >= SIO_START_ADDRESS && address < SIO_START_ADDRESS + 0x10000000 {
        let sio_address = address - SIO_START_ADDRESS;
        let mut pin_list: Vec<u32> = Vec::new();
        for index in 0..32 {
            if value & (1 << index) > 0 {
                pin_list.push(index);
            }
        }
        if sio_address == 20 {
            println!(
                "GPIO pins {} set to HIGH",
                pin_list
                    .iter()
                    .map(|pin| pin.to_string() + ", ")
                    .collect::<String>()
            );
        } else if sio_address == 24 {
            println!(
                "GPIO pins {} set to LOW",
                pin_list
                    .iter()
                    .map(|pin| pin.to_string() + ", ")
                    .collect::<String>()
            );
        } else {
            println!("Someone wrote {:#08x} to {:#08x}", value, sio_address);
        }
    }
}

pub fn execute_instruction(rp2040: &mut RP2040) {
    let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
    // ARM Thumb instruction encoding - 16 bits / 2 bytes
    let opcode = flash16[(rp2040.registers[PC] / 2) as usize];
    let opcode2 = flash16[(rp2040.registers[PC] / 2 + 1) as usize];
    // B
    if opcode >> 11 == 0b11100 {
        let mut imm11 = ((opcode & 0x7ff) << 1) as u32;
        if imm11 & (1 << 11) != 0 {
            imm11 = (imm11 & 0x7ff).wrapping_sub(0x800);
        }
        rp2040.registers[PC] = rp2040.registers[PC].wrapping_add(imm11 + 2);
    }
    // BL
    if (opcode >> 11 == 0b11110) && (opcode2 >> 14 == 0b11) {
        // right now we just ignore it. but let's print it!
        println!("BL ignored");
    }
    // LSLS
    else if opcode >> 11 == 0b00000 {
        let imm5 = (opcode >> 6) & 0x1f;
        let rm = ((opcode >> 3) & 0x7) as usize;
        let rd = (opcode & 0x7) as usize;
        rp2040.registers[rd] = rp2040.registers[rm] << imm5;
        // update flags
        // APSR.N = result<31>;
        // APSR.Z = IsZeroBit(result);
        // APSR.C = carry;
        // APSR.V unchanged
    }
    // MOVS
    else if opcode >> 11 == 0b00100 {
        let value = (opcode & 0xff) as u32;
        let rd = ((opcode >> 8) & 7) as usize;
        rp2040.registers[rd] = value;
        // update status flags (if InITBlock)?
        // APSR.N = result<31>;
        // APSR.Z = IsZeroBit(result);
        // APSR.C = carry;
        // APSR.V unchanged
    }
    // PUSH
    else if opcode >> 9 == 0b1011010 {
        let mut bit_count = 0;
        for index in 0..9 {
            if opcode & (1 << index) != 0 {
                bit_count += 1;
            }
        }
        let mut address = rp2040.registers[SP] - 4 * bit_count;
        for index in 0..8 {
            if opcode & (1 << index) != 0 {
                write_u32(rp2040, address, rp2040.registers[index as usize]);
                address += 4;
            }
        }
        if opcode & (1 << 8) != 0 {
            write_u32(rp2040, address, rp2040.registers[LR]);
        }
        rp2040.registers[SP] -= 4 * bit_count;
    }
    // STR (immediate)
    else if opcode >> 11 == 0b01100 {
        let imm5 = (((opcode >> 6) & 0x1f) << 2) as u32;
        let rn = ((opcode >> 3) & 0x7) as usize;
        let rt = (opcode & 0x7) as usize;
        let address = rp2040.registers[rn] + imm5;
        write_u32(rp2040, address, rp2040.registers[rt]);
    }

    rp2040.registers[PC] += 2;
}

#[cfg(test)]
mod execute_instruction_test {
    use crate::rp2040::*;

    /**
     * Should execute a `push {r4, r5, r6, lr}` instruction
     */
    #[test]
    fn push_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        rp2040.registers[SP] = RAM_START_ADDRESS + 0x100;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0xB570; // push {r4, r5, r6, lr}
        rp2040.registers[4] = 0x40;
        rp2040.registers[5] = 0x50;
        rp2040.registers[6] = 0x60;
        rp2040.registers[LR] = 0x42;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[SP], RAM_START_ADDRESS + 0xF0);
        assert_eq!(rp2040.sram[0xF0], 0x40);
        assert_eq!(rp2040.sram[0xF4], 0x50);
        assert_eq!(rp2040.sram[0xF8], 0x60);
        assert_eq!(rp2040.sram[0xFC], 0x42);
    }

    /**
     * Should execute a `movs r5, #128` instruction
     */
    #[test]
    fn movs_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x2580; // movs r5, #128
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[5], 128);
        assert_eq!(rp2040.registers[PC], 2);
    }

    /**
     * Should execute a `movs r6, r5` instruction
     */
    #[test]
    fn movs_instruction_2() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x002E; // movs r6, r5
        rp2040.registers[5] = 0x50;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[6], 0x50);
    }

    /**
     * Should execute a `lsls r5, r5, #18` instruction
     */
    #[test]
    fn lsls_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x04AD; // lsls r5, r5, #18
        rp2040.registers[5] = 0b00000000000000000011;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[5], 0b11000000000000000000);
        assert_eq!(rp2040.registers[PC], 2);
    }

    /**
     * Should execute a `str r6, [r4, #20]` instruction
     */
    #[test]
    fn str_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x6166; // str r6, [r4, #20]
        rp2040.registers[4] = RAM_START_ADDRESS + 0x20;
        rp2040.registers[6] = 0xF00D;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.sram[0x20 + 20], 0x0D);
        assert_eq!(rp2040.sram[0x20 + 21], 0xF0);
        assert_eq!(rp2040.registers[PC], 2);
    }

    /**
     * Should execute a `b.n .-20` instruction
     */
    #[test]
    fn bn_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 9 * 2;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[9] = 0xE7F6; // b.n .-20
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[PC], 2);
    }
}
