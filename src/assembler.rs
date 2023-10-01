#[cfg(test)]
pub mod assembler_test {
    pub fn opcode_adcs(rdn: usize, rm: usize) -> u16 {
        return (0b0100000101 << 6) | ((rm as u16 & 7) << 3) | (rdn as u16 & 7);
    }

    pub fn opcode_adds2(rdn: usize, imm8: u16) -> u16 {
        return (0b00110 << 11) | ((rdn as u16 & 7) << 8) | (imm8 as u16 & 0xff);
    }

    pub fn opcode_ldrb(rt: usize, rn: usize, imm5: u16) -> u16 {
        return (0b01111 << 11)
            | ((imm5 & 0x1f) << 6)
            | ((rn as u16 & 0x7) << 3)
            | (rt as u16 & 0x7);
    }

    pub fn opcode_rsbs(rd: usize, rn: usize) -> u16 {
        return (0b0100001001 << 6) | ((rn as u16 & 0x7) << 3) | (rd as u16 & 0x7);
    }

    pub fn opcode_subs2(rdn: usize, imm8: u16) -> u16 {
        return (0b00111 << 11) | ((rdn as u16 & 7) << 8) | (imm8 & 0xff);
    }

    pub fn opcode_uxtb(rd: usize, rm: usize) -> u16 {
        return (0b1011001011 << 6) | ((rm as u16 & 7) << 3) | (rd as u16 & 7);
    }

    /*
     * Should correctly encode an `adc r3, r0` instruction
     */
    #[test]
    fn adcs_assembler() {
        assert_eq!(opcode_adcs(3, 0), 0x4143);
    }

    /*
     * Should correctly encode an `adds r1, #1` instruction
     */
    #[test]
    fn adds_assembler() {
        assert_eq!(opcode_adds2(1, 1), 0x3101);
    }

    /*
     * Should correctly encode an `ldrb r0, [r1, #0]` instruction
     */
    #[test]
    fn ldrb_assembler() {
        assert_eq!(opcode_ldrb(0, 1, 0), 0x7808);
    }

    /*
     * Should correctly encode an `rsbs r0, r3` instruction
     */
    #[test]
    fn rsbs_assembler() {
        assert_eq!(opcode_rsbs(0, 3), 0x4258);
    }

    /*
     * Should correctly encode an `subs r3, #13` instruction
     */
    #[test]
    fn subs_assembler() {
        assert_eq!(opcode_subs2(3, 13), 0x3B0D);
    }

    /*
     * Should correctly encode an `uxtb r3, r3` instruction
     */
    #[test]
    fn uxtb_assembler() {
        assert_eq!(opcode_uxtb(3, 3), 0xB2DB);
    }
}
