pub struct Tcp<'pkt> {
    slice: &'pkt mut [u8],
    size: TcpSize,
}

pub enum Error {
    InvalidSize(usize),
    InvalidSizeForOffset(usize, TcpSize),
    InvalidDataOffset(DataOffsetError),
}

impl<'pkt> Tcp<'pkt> {
    pub const MIN_LEN: usize = 20;
    pub const MAX_LEN: usize = 60;

    pub fn new(slice: &'pkt mut [u8]) -> Result<(Self, &'pkt mut [u8]), Error> {
        if slice.len() < Self::MIN_LEN {
            return Err(Error::InvalidSize(slice.len()));
        }

        let size = TcpSize::try_from_data_offset_u8(slice[12] >> 4)
            .map_err(|e| Error::InvalidDataOffset(e))?;

        if slice.len() < size as usize {
            return Err(Error::InvalidSizeForOffset(slice.len(), size));
        }

        let (slice, rem) = slice.split_at_mut(size as usize);

        Ok((Self { slice, size }, rem))
    }
}

impl Tcp<'_> {
    pub fn size(&self) -> TcpSize {
        self.size
    }

    pub fn set_destination(&mut self, port: u16) {
        self.slice[2..4].copy_from_slice(&port.to_be_bytes())
    }

    pub fn destination(&self) -> u16 {
        u16::from_be_bytes(*self.slice[2..4].first_chunk::<2>().unwrap())
    }

    pub fn source(&self) -> u16 {
        u16::from_be_bytes(*self.slice[0..2].first_chunk::<2>().unwrap())
    }

    pub fn set_source(&mut self, port: u16) {
        self.slice[0..2].copy_from_slice(&port.to_be_bytes())
    }

    pub fn window_size(&self) -> u16 {
        u16::from_be_bytes(*self.slice[14..16].first_chunk::<2>().unwrap())
    }

    pub fn set_window_size(&mut self, window_size: u16) {
        self.slice[14..16].copy_from_slice(&window_size.to_be_bytes())
    }

    pub fn slice(&self) -> &[u8] {
        &self.slice
    }

    pub fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.slice
    }

    pub fn csum(&self) -> u16 {
        u16::from_be_bytes(*self.slice[16..18].first_chunk::<2>().unwrap())
    }

    pub fn set_csum(&mut self, csum: u16) {
        self.slice[16..18].copy_from_slice(&csum.to_be_bytes())
    }

    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes(*self.slice[18..20].first_chunk::<2>().unwrap())
    }

    pub fn set_urgent_pointer(&mut self, urgent_pointer: u16) {
        self.slice[18..20].copy_from_slice(&urgent_pointer.to_be_bytes())
    }

    pub fn sequence_num(&self) -> u32 {
        u32::from_be_bytes(*self.slice[4..8].first_chunk::<4>().unwrap())
    }

    pub fn set_sequence_num(&mut self, num: u32) {
        self.slice[4..8].copy_from_slice(&num.to_be_bytes())
    }

    pub fn ack_num(&self) -> u32 {
        u32::from_be_bytes(*self.slice[8..12].first_chunk::<4>().unwrap())
    }

    pub fn set_ack_num(&mut self, ack: u32) {
        self.slice[8..12].copy_from_slice(&ack.to_be_bytes())
    }

    pub fn data_offset(&self) -> u8 {
        self.slice[12] >> 4
    }

    pub fn set_data_offset(&mut self, data_offset: u8) {
        self.slice[12] = data_offset << 4
    }

    pub fn flags(&self) -> u8 {
        self.slice[13]
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.slice[13] = flags
    }

    pub fn options(&self) -> &[u8] {
        &self.slice[Self::MIN_LEN..self.size as usize]
    }

    pub fn cwr(&self) -> bool {
        self.slice[13] >> 7 == 1
    }

    pub fn ece(&self) -> bool {
        (self.slice[13] >> 6) & 1 == 1
    }

    pub fn urg(&self) -> bool {
        (self.slice[13] >> 5) & 1 == 1
    }

    pub fn ack(&self) -> bool {
        (self.slice[13] >> 4) & 1 == 1
    }

    pub fn psh(&self) -> bool {
        (self.slice[13] >> 3) & 1 == 1
    }

    pub fn rst(&self) -> bool {
        (self.slice[13] >> 2) & 1 == 1
    }

    pub fn syn(&self) -> bool {
        (self.slice[13] >> 1) & 1 == 1
    }

    pub fn fin(&self) -> bool {
        self.slice[13] & 1 == 1
    }

    pub fn ns(&self) -> bool {
        self.slice[12] & 1 == 1
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[repr(usize)]
pub enum TcpSize {
    S20 = 20,
    S24 = 24,
    S28 = 28,
    S32 = 32,
    S36 = 36,
    S40 = 40,
    S44 = 44,
    S48 = 48,
    S52 = 52,
    S56 = 56,
    S60 = 60,
}

impl TcpSize {
    pub fn try_from_data_offset_u8(ihl: u8) -> Result<Self, DataOffsetError> {
        Ok(match ihl {
            5 => TcpSize::S20,
            6 => TcpSize::S24,
            7 => TcpSize::S28,
            8 => TcpSize::S32,
            9 => TcpSize::S36,
            10 => TcpSize::S40,
            11 => TcpSize::S44,
            12 => TcpSize::S48,
            13 => TcpSize::S52,
            14 => TcpSize::S56,
            15 => TcpSize::S60,
            x => {
                return Err(DataOffsetError::InvalidOffset(x));
            }
        })
    }
}

#[derive(Debug)]
pub enum DataOffsetError {
    InvalidOffset(u8),
}