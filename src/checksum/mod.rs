/// Computing the Internet Checksum (RFC 1071)
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u64 = 0; // u64 is big enough to store the internet checksum
    let mut range: (usize, usize) = (0, 1);

    while range.1 < data.len() {
        sum += ((data[range.0] as u64) << 8) | (data[range.1] as u64);
        range.0 += 2;
        range.1 += 2;
    }

    if range.0 < data.len() {
        sum += (data[range.0] as u64) << 8;
    }

    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16)
    }

    !sum as u16
}

#[cfg(test)]
mod tests {

    #[test]
    fn checksum() {
        let bytes: Vec<u8> = vec![
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x00, 0x00, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34,
            0x56, 0x78,
        ];
        let result = super::checksum(bytes.as_slice());
        assert_eq!(0x2918, result);
    }
}
