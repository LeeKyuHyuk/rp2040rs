use std::{fs::File, io::Read};

use crate::rp2040::FLASH_SIZE;

pub fn load_hex(filename: &str) -> Vec<u8> {
    let mut hex_file = File::open(filename).expect("File not found");
    let mut source = String::new();
    hex_file
        .read_to_string(&mut source)
        .expect("Something went wrong reading the file");
    let mut target: Vec<u8> = vec![0xFF; FLASH_SIZE];
    for line in source.split('\n') {
        if !line.is_empty() {
            let start_record = &line[0..1];
            let record_type = &line[7..9];
            if (start_record == ":") && (record_type == "00") {
                let bytes = usize::from_str_radix(&line[1..3], 16)
                    .expect("There was a problem converting the data");
                let address = usize::from_str_radix(&line[3..7], 16)
                    .expect("There was a problem converting the data");
                for index in 0..bytes {
                    let data_byte_offset = 9 + index * 2;
                    target[address + index] =
                        u8::from_str_radix(&line[data_byte_offset..(data_byte_offset + 2)], 16)
                            .expect("There was a problem converting the data");
                }
            }
        }
    }
    return target;
}
