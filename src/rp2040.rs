use std::{collections::HashMap, mem::size_of, slice::from_raw_parts_mut};

use crate::intelhex::load_hex;

const FLASH_START_ADDRESS: u32 = 0x10000000;
const RAM_START_ADDRESS: u32 = 0x20000000;
const SIO_START_ADDRESS: u32 = 0xD0000000;

const SP: usize = 13;
const LR: usize = 14;
pub const PC: usize = 15;

pub const SRAM_SIZE: usize = 264 * 1024;
pub const FLASH_SIZE: usize = 16 * 1024 * 1024;
pub const NUMBER_OF_REGISTERS: usize = 16;

type CpuWriteCallback = fn(address: u32, value: u32);
type CpuReadCallback = fn(address: u32) -> u32;

pub struct RP2040 {
    pub sram: Vec<u8>,
    pub flash: Vec<u8>,
    pub registers: [u32; NUMBER_OF_REGISTERS],
    pub n: bool,
    pub c: bool,
    pub z: bool,
    pub v: bool,
    pub write_hooks: HashMap<u32, CpuWriteCallback>,
    pub read_hooks: HashMap<u32, CpuReadCallback>,
}

pub fn initialize(filename: &str) -> RP2040 {
    let mut rp2040 = RP2040 {
        sram: vec![0x00; SRAM_SIZE],
        flash: vec![0xFF; FLASH_SIZE],
        registers: [0x00; NUMBER_OF_REGISTERS],
        n: false,
        c: false,
        z: false,
        v: false,
        write_hooks: HashMap::new(),
        read_hooks: HashMap::new(),
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

fn sign_extend8(value: u32) -> i32 {
    if value & 0x80 != 0 {
        return (0x80000000 + (value & 0x7F)) as i32;
    } else {
        value as i32
    }
}

fn sign_extend16(value: u32) -> i32 {
    if value & 0x8000 != 0 {
        return (0x80000000 + (value & 0x7FFF)) as i32;
    } else {
        value as i32
    }
}

fn check_condition(rp2040: &mut RP2040, cond: u16) -> bool {
    // Evaluate base condition.
    let mut result = false;
    if cond.wrapping_shr(1) == 0b000 {
        result = rp2040.z;
    } else if cond.wrapping_shr(1) == 0b001 {
        result = rp2040.c;
    } else if cond.wrapping_shr(1) == 0b010 {
        result = rp2040.n;
    } else if cond.wrapping_shr(1) == 0b011 {
        result = rp2040.v;
    } else if cond.wrapping_shr(1) == 0b100 {
        result = rp2040.c && rp2040.z;
    } else if cond.wrapping_shr(1) == 0b101 {
        result = rp2040.n == rp2040.v;
    } else if cond.wrapping_shr(1) == 0b110 {
        result = rp2040.n == rp2040.v && rp2040.z;
    } else if cond.wrapping_shr(1) == 0b111 {
        result = true;
    }
    if cond & 0b1 != 0 && cond != 0b1111 {
        return !result;
    } else {
        return result;
    }
}

fn get_u32(array: &Vec<u8>, offset: u32) -> u32 {
    let mut result: u32 = 0;
    for index in 0..4 {
        result |= (array[(offset + index) as usize] as u32) << (index * 8);
    }
    return result;
}

fn read_u32(rp2040: &mut RP2040, address: u32) -> u32 {
    if address < FLASH_START_ADDRESS {
        // TODO: should be readonly from bootrom once we have it
        return get_u32(&rp2040.flash, address);
    } else if address >= FLASH_START_ADDRESS && address < RAM_START_ADDRESS {
        return get_u32(&rp2040.flash, address - FLASH_START_ADDRESS);
    } else if address >= RAM_START_ADDRESS && address < RAM_START_ADDRESS + (SRAM_SIZE as u32) {
        return get_u32(&rp2040.sram, address - RAM_START_ADDRESS);
    } else {
        if let Some(callback) = rp2040.read_hooks.get(&address) {
            return callback(address);
        }
    }
    println!("Read from invalid memory address: {:#08x}", address);
    return 0xFFFFFFFF;
}

fn read_u16(rp2040: &mut RP2040, address: u32) -> u16 {
    return (read_u32(rp2040, address) & 0xFFFF) as u16;
}

fn read_u8(rp2040: &mut RP2040, address: u32) -> u8 {
    return (read_u32(rp2040, address) & 0xFF) as u8;
}

fn write_u32(rp2040: &mut RP2040, address: u32, value: u32) {
    if address >= RAM_START_ADDRESS && address < RAM_START_ADDRESS + (SRAM_SIZE as u32) {
        rp2040.sram[(address - RAM_START_ADDRESS) as usize..][..4]
            .copy_from_slice(&value.to_le_bytes());
    } else if address >= SIO_START_ADDRESS && address < SIO_START_ADDRESS + 0x10000000 {
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
    } else {
        if let Some(callback) = rp2040.write_hooks.get(&address) {
            return callback(address, value);
        }
    }
}

pub fn execute_instruction(rp2040: &mut RP2040) {
    let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
    // ARM Thumb instruction encoding - 16 bits / 2 bytes
    let opcode = flash16[(rp2040.registers[PC] / 2) as usize];
    let opcode2 = flash16[(rp2040.registers[PC] / 2 + 1) as usize];
    let opcode_pc = rp2040.registers[PC];
    rp2040.registers[PC] += 2;
    // ADCS
    if opcode >> 6 == 0b0100000101 {
        let rm = ((opcode >> 3) & 0x7) as usize;
        let rdn = (opcode & 0x7) as usize;
        let left_value = rp2040.registers[rdn];
        let right_value = rp2040.registers[rm];
        let result = left_value
            .wrapping_add(right_value)
            .wrapping_add(if rp2040.c { 1 } else { 0 });
        rp2040.registers[rdn] = result;
        rp2040.n = !!(result & 0x80000000 != 0);
        rp2040.z = (result & 0xFFFFFFFF) == 0;
        rp2040.c = result >= 0xFFFFFFFF;
        rp2040.v = ((left_value as i32) >= 0 && (right_value as i32) >= 0 && (result as i32) < 0)
            || ((left_value as i32) <= 0 && (right_value as i32) <= 0 && (result as i32) > 0);
    }
    // ADDS (Encoding T2)
    else if opcode >> 11 == 0b00110 {
        let imm8 = opcode & 0xFF;
        let rdn = ((opcode >> 8) & 0x7) as usize;
        let left_value = rp2040.registers[rdn] as u64;
        let result = left_value.wrapping_add(imm8 as u64);
        rp2040.registers[rdn] = result as u32;
        rp2040.n = !!(result & 0x80000000 != 0);
        rp2040.z = (result & 0xFFFFFFFF) == 0;
        rp2040.c = result >= 0xFFFFFFFF;
        rp2040.v = (left_value as i32) > 0 && imm8 < 0x80 && (result as i32) < 0;
    }
    // B (with cond)
    else if opcode >> 12 == 0b1101 {
        let mut imm8 = (opcode & 0xFF).wrapping_shl(1) as u32;
        let cond = (opcode >> 8) & 0xF;
        if (imm8 & (1 << 8)) != 0 {
            imm8 = (imm8 & 0x1ff).wrapping_sub(0x200);
        }
        if check_condition(rp2040, cond) {
            rp2040.registers[PC] = rp2040.registers[PC].wrapping_add(imm8 as u32 + 2);
        }
    }
    // B
    else if opcode >> 11 == 0b11100 {
        let mut imm11 = (opcode & 0x7FF).wrapping_shl(1) as u32;
        if imm11 & (1 << 11) != 0 {
            imm11 = (imm11 & 0x7FF).wrapping_sub(0x800);
        }
        rp2040.registers[PC] = rp2040.registers[PC].wrapping_add(imm11 as u32 + 2);
    }
    // BL
    else if (opcode >> 11 == 0b11110) && (opcode2 >> 14 == 0b11) {
        // right now we just ignore it. but let's print it!
        println!("BL ignored");
        rp2040.registers[PC] += 2;
    }
    // CMP immediate
    else if opcode >> 11 == 0b00101 {
        let rn = ((opcode >> 8) & 0x7) as usize;
        let imm8 = opcode & 0xFF;
        let value = rp2040.registers[rn] as i32;
        let result = value.wrapping_sub(imm8 as i32);
        rp2040.n = value < imm8 as i32;
        rp2040.z = value == imm8 as i32;
        rp2040.c = value >= imm8 as i32;
        rp2040.v = value < 0 && imm8 > 0 && result > 0;
    }
    // CMP (register)
    else if opcode >> 6 == 0b0100001010 {
        let rm = ((opcode >> 3) & 0x7) as usize;
        let rn = (opcode & 0x7) as usize;
        let left_value = rp2040.registers[rn] as i32;
        let right_value = rp2040.registers[rm] as i32;
        let result = left_value - right_value;
        rp2040.n = left_value < right_value;
        rp2040.z = left_value == right_value;
        rp2040.c = left_value >= right_value;
        rp2040.v = (left_value > 0 && right_value < 0 && result < 0)
            || (left_value < 0 && right_value > 0 && result > 0);
    }
    // LDR (immediate)
    else if opcode >> 11 == 0b01101 {
        let imm5 = ((opcode >> 6) & 0x1F).wrapping_shl(2);
        let rn = ((opcode >> 3) & 0x7) as usize;
        let rt = (opcode & 0x7) as usize;
        let addr = rp2040.registers[rn] + imm5 as u32;
        rp2040.registers[rt] = read_u32(rp2040, addr);
    }
    // LDR (literal)
    else if opcode >> 11 == 0b01001 {
        let imm8 = (opcode & 0xFF) << 2;
        let rt = ((opcode >> 8) & 7) as usize;
        let next_pc = rp2040.registers[PC] + 2;
        let addr = (next_pc & 0xFFFFFFFC).wrapping_add(imm8 as u32);
        println!("reading from {:#08x}", addr);
        rp2040.registers[rt] = read_u32(rp2040, addr);
    }
    // LDRB (immediate)
    else if opcode >> 11 == 0b01111 {
        let imm5 = (opcode >> 6) & 0x1F;
        let rn = ((opcode >> 3) & 0x7) as usize;
        let rt = (opcode & 0x7) as usize;
        let addr = rp2040.registers[rn].wrapping_add(imm5 as u32);
        rp2040.registers[rt] = read_u8(rp2040, addr) as u32;
    }
    // LDRSH (immediate)
    else if opcode >> 9 == 0b0101111 {
        let rm = ((opcode >> 6) & 0x7) as usize;
        let rn = ((opcode >> 3) & 0x7) as usize;
        let rt = (opcode & 0x7) as usize;
        let addr = rp2040.registers[rm].wrapping_add(rp2040.registers[rn]);
        rp2040.registers[rt] = sign_extend16(read_u16(rp2040, addr) as u32) as u32;
    }
    // LSLS
    else if opcode >> 11 == 0b00000 {
        let imm5 = (opcode >> 6) & 0x1F;
        let rm = ((opcode >> 3) & 0x7) as usize;
        let rd = (opcode & 0x7) as usize;
        let input = rp2040.registers[rm];
        let result = input.wrapping_shl(imm5 as u32);
        rp2040.registers[rd] = result;
        rp2040.n = !!(result & 0x80000000 != 0);
        rp2040.z = result == 0;
        if imm5 != 0 {
            rp2040.c = !!(input & (1 << (32 - imm5)) != 0);
        }
    }
    // MOVS
    else if opcode >> 11 == 0b00100 {
        let value = (opcode & 0xFF) as u32;
        let rd = ((opcode >> 8) & 7) as usize;
        rp2040.registers[rd] = value;
        rp2040.n = !!(value & 0x80000000 != 0);
        rp2040.z = value == 0;
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
    // NEGS
    else if opcode >> 6 == 0b0100001001 {
        let rn = ((opcode >> 3) & 0x7) as usize;
        let rd = (opcode & 0x7) as usize;
        let value = rp2040.registers[rn] as i32;
        rp2040.registers[rd] = (-value) as u32;
        rp2040.n = value > 0;
        rp2040.z = value == 0;
        rp2040.c = value == -1;
        rp2040.v = value == 0x7FFFFFFF;
    }
    // STR (immediate)
    else if opcode >> 11 == 0b01100 {
        let imm5 = ((opcode >> 6) & 0x1F).wrapping_shl(2);
        let rn = ((opcode >> 3) & 0x7) as usize;
        let rt = (opcode & 0x7) as usize;
        let address = rp2040.registers[rn] + imm5 as u32;
        write_u32(rp2040, address, rp2040.registers[rt]);
    }
    // SUBS (Encoding T2)
    else if opcode >> 11 == 0b00111 {
        let imm8 = opcode & 0xFF;
        let rdn = ((opcode >> 8) & 0x7) as usize;
        let value = rp2040.registers[rdn];
        let result = value.wrapping_sub(imm8 as u32) as i32;
        rp2040.registers[rdn] = result as u32;
        rp2040.n = value < imm8 as u32;
        rp2040.z = value == imm8 as u32;
        rp2040.c = value >= imm8 as u32;
        rp2040.v = (value as i32) < 0 && imm8 > 0 && result > 0;
    }
    // TST
    else if opcode >> 6 == 0b0100001000 {
        let rm = ((opcode >> 3) & 0x7) as usize;
        let rn = (opcode & 0x7) as usize;
        let result = rp2040.registers[rn] & rp2040.registers[rm];
        rp2040.n = !!(result & 0x80000000 != 0);
        rp2040.z = result == 0;
    }
    // UXTB
    else if opcode >> 6 == 0b1011001011 {
        let rm = ((opcode >> 3) & 0x7) as usize;
        let rd = (opcode & 0x7) as usize;
        rp2040.registers[rd] = rp2040.registers[rm] & 0xFF;
    } else {
        println!(
            "Warning: Instruction at {:#08x} is not implemented yet!",
            opcode_pc
        );
    }
}

#[cfg(test)]
mod execute_instruction_test {
    use crate::assembler::assembler_test::*;
    use crate::rp2040::*;

    /**
     * Should execute a `adcs r5, r4` instruction
     */
    #[test]
    fn adcs_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = opcode_adcs(5, 4);
        rp2040.registers[4] = 55;
        rp2040.registers[5] = 66;
        rp2040.c = true;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[5], 122);
        assert_eq!(rp2040.n, false);
        assert_eq!(rp2040.z, false);
        assert_eq!(rp2040.c, false);
        assert_eq!(rp2040.v, false);
    }

    /**
     * Should execute a `adcs r5, r4` instruction
     */
    #[test]
    fn adcs_instruction_2() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = opcode_adcs(5, 4);
        rp2040.registers[4] = 0x7FFFFFFF; // Max signed INT32
        rp2040.registers[5] = 0;
        rp2040.c = true;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[5], 0x80000000);
        assert_eq!(rp2040.n, true);
        assert_eq!(rp2040.z, false);
        assert_eq!(rp2040.c, false);
        assert_eq!(rp2040.v, true);
    }

    /**
     * Should execute a `adds r1, #1` instruction
     */
    #[test]
    fn adds_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = opcode_adds2(1, 1);
        rp2040.registers[1] = 0xFFFFFFFF;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[1], 0x0);
        assert_eq!(rp2040.n, false);
        assert_eq!(rp2040.z, true);
        assert_eq!(rp2040.c, true);
        assert_eq!(rp2040.v, false);
    }

    /**
     * Should execute `adds r1, #1` instruction and set the overflow flag correctly
     */
    #[test]
    fn adds_instruction_2() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = opcode_adds2(1, 1);
        rp2040.registers[1] = 0x7FFFFFFF;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[1], 0x80000000);
        assert_eq!(rp2040.n, true);
        assert_eq!(rp2040.z, false);
        assert_eq!(rp2040.c, false);
        assert_eq!(rp2040.v, true);
    }

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
     * Should execute a `lsls r5, r5, #18` instruction with carry
     */
    #[test]
    fn lsls_instruction_2() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x04AD; // lsls r5, r5, #18
        rp2040.registers[5] = 0x00004001;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[5], 0x40000);
        assert_eq!(rp2040.c, true);
    }

    /**
     * Should execute a `rsbs r0, r3` instruction
     */
    #[test]
    fn rsbs_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = opcode_rsbs(0, 3);
        rp2040.registers[3] = 100;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[0] as i32, -100);
        assert_eq!(rp2040.n, true);
        assert_eq!(rp2040.z, false);
        assert_eq!(rp2040.c, false);
        assert_eq!(rp2040.v, false);
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
        assert_eq!(get_u32(&rp2040.sram, 0x20 + 20), 0xF00D);
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

    /**
     * Should execute a `bne.n .-6` instruction
     */
    #[test]
    fn bne_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 9 * 2;
        rp2040.z = false;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[9] = 0xD1FC; // bne.n .-6
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[PC], 14);
    }

    /**
     * Should execute a `cmp r5, #66` instruction
     */
    #[test]
    fn cmp_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x2D42; // cmp r5, #66
        rp2040.registers[5] = 60;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.n, true);
        assert_eq!(rp2040.z, false);
        assert_eq!(rp2040.c, false);
        assert_eq!(rp2040.v, false);
    }

    /**
     * Should execute a `cmp r5, r0` instruction
     */
    #[test]
    fn cmp_instruction_2() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x4285; // cmp r5, r0
        rp2040.registers[5] = 60;
        rp2040.registers[0] = 56;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.n, false);
        assert_eq!(rp2040.z, false);
        assert_eq!(rp2040.c, true);
        assert_eq!(rp2040.v, false);
    }

    /**
     * Should execute a `ldr r0, [pc, #148]` instruction
     */
    #[test]
    fn ldr_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x4825; // ldr r0, [pc, #148]
        rp2040.flash[152] = 0x42;
        rp2040.flash[153] = 0x00;
        rp2040.flash[154] = 0x00;
        rp2040.flash[155] = 0x00;
        rp2040.flash[156] = 0x00;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[0], 0x42);
        assert_eq!(rp2040.registers[PC], 2);
    }

    /**
     * Should execute a `ldr r3, [r2, #24]` instruction
     */
    #[test]
    fn ldr_instruction_2() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x6993; // ldr r3, [r2, #24]
        rp2040.registers[2] = 0x20000000;
        rp2040.sram[24] = 0x55;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[3], 0x55);
    }

    /**
     * Should execute a `ldrb r4, [r2, 5]` instruction
     */
    #[test]
    fn ldrb_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = opcode_ldrb(4, 2, 5);
        rp2040.registers[2] = 0x20000000;
        rp2040.sram[5] = 0x66;
        rp2040.sram[6] = 0x77;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[4], 0x66);
    }

    /**
     * Should execute a `ldrsh r5, [r3, r5]` instruction
     */
    #[test]
    fn ldrsh_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x5F5D; // ldrsh r5, [r3, r5]
        rp2040.registers[3] = 0x20000000;
        rp2040.registers[5] = 6;
        rp2040.sram[6] = 0x55;
        rp2040.sram[7] = 0xF0;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[5], 0x80007055);
    }

    /**
     * Should execute a `subs r5, #10` instruction
     */
    #[test]
    fn subs_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = opcode_subs2(5, 10);
        rp2040.registers[5] = 100;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[5], 90);
        assert_eq!(rp2040.n, false);
        assert_eq!(rp2040.z, false);
        assert_eq!(rp2040.c, true);
        assert_eq!(rp2040.v, false);
    }

    /**
     * Should execute a `subs r1, #1` instruction with overflow
     */
    #[test]
    fn subs_instruction_2() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = opcode_subs2(1, 1);
        rp2040.registers[1] = (-0x80000000 as i32) as u32;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[1], 0x7FFFFFFF);
        assert_eq!(rp2040.n, false);
        assert_eq!(rp2040.z, false);
        assert_eq!(rp2040.c, true);
        assert_eq!(rp2040.v, true);
    }

    /**
     * Should execute an `tst r1, r3` instruction when the result is negative
     */
    #[test]
    fn tst_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x4219; // tst r1, r3
        rp2040.registers[1] = 0xF0000000;
        rp2040.registers[3] = 0xF0004000;
        rp2040.sram[24] = 0x55;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.n, true);
    }

    /**
     * Should execute an `tst r1, r3` instruction the registers are equal
     */
    #[test]
    fn tst_instruction_2() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = 0x4219; // tst r1, r3
        rp2040.registers[1] = 0;
        rp2040.registers[3] = 55;
        rp2040.sram[24] = 0x55;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.z, true);
    }

    /**
     * Should execute an `uxtb r5, r3` instruction the registers are equal'
     */
    #[test]
    fn uxtb_instruction_1() {
        let mut rp2040 = initialize("");
        rp2040.registers[PC] = 0x0;
        let flash16 = get_flash16_ptr_mut(&mut rp2040.flash);
        flash16[0] = opcode_uxtb(5, 3);
        rp2040.registers[3] = 0x12345678;
        execute_instruction(&mut rp2040);
        assert_eq!(rp2040.registers[5], 0x78);
    }
}
