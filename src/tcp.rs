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
    pub fn source(&self) -> u16 {
        u16::from_be_bytes(*self.slice[0..2].first_chunk::<2>().unwrap())
    }

    pub fn destination(&self) -> u16 {
        u16::from_be_bytes(*self.slice[2..4].first_chunk::<2>().unwrap())
    }

    pub fn set_source(&mut self, port: u16) {
        self.slice[0..2].copy_from_slice(&port.to_be_bytes())
    }

    pub fn set_destination(&mut self, port: u16) {
        self.slice[2..4].copy_from_slice(&port.to_be_bytes())
    }

    pub fn sequence_num(&mut self) -> u32 {
        u32::from_be_bytes(*self.slice[4..8].first_chunk::<4>().unwrap())
    }

    pub fn set_sequence_num(&mut self, num: u32) {
        self.slice[4..8].copy_from_slice(&num.to_be_bytes())
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
