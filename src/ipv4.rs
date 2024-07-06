pub struct IPv4<'pkt> {
    slice: &'pkt mut [u8],
    size: IPv4Size,
}

#[derive(Debug)]
pub enum IhlError {
    InvalidIhl(u8),
}

pub enum Error {
    InvalidIhl(IhlError),
    InvalidSize(usize),
    InvalidSizeForIhl(usize, IPv4Size),
    InvalidVersion(u8),
}

impl<'pkt> IPv4<'pkt> {
    pub const MIN_LEN: usize = 20;
    pub const MAX_LEN: usize = 60;

    pub fn get_version(&self) -> u8 {
        self.slice[0] >> 4
    }

    pub fn get_source(&self) -> &[u8; 4] {
        self.slice[12..16].first_chunk::<4>().unwrap()
    }

    pub fn set_source(&mut self, source: &[u8; 4]) {
        self.slice[12..16].copy_from_slice(source)
    }

    pub fn get_source_u32(&self) -> u32 {
        u32::from_be_bytes(*self.slice[12..16].first_chunk::<4>().unwrap())
    }

    pub fn set_source_u32(&mut self, source: u32) {
        self.slice[12..16].copy_from_slice(&source.to_be_bytes())
    }

    pub fn get_destination_u32(&self) -> u32 {
        u32::from_be_bytes(*self.slice[16..20].first_chunk::<4>().unwrap())
    }

    pub fn set_destination_u32(&mut self, destination: u32) {
        self.slice[16..20].copy_from_slice(&destination.to_be_bytes())
    }

    pub fn get_destination(&self) -> &[u8; 4] {
        self.slice[16..20].first_chunk::<4>().unwrap()
    }

    pub fn set_destination(&mut self, destination: &[u8; 4]) {
        self.slice[16..20].copy_from_slice(destination)
    }

    pub fn get_dscp(&self) -> u8 {
        self.slice[1] >> 2
    }

    pub fn get_ecn(&self) -> u8 {
        self.slice[1] & 0b11
    }

    pub fn get_total_length(&self) -> &[u8; 2] {
        self.slice[2..4].first_chunk::<2>().unwrap()
    }

    pub fn set_total_length(&mut self, value: &[u8; 2]) {
        self.slice[2..4].copy_from_slice(value)
    }

    pub fn get_total_length_u16(&self) -> u16 {
        u16::from_be_bytes(*self.slice[2..4].first_chunk::<2>().unwrap())
    }

    pub fn set_total_length_u16(&mut self, value: u16) {
        self.slice[2..4].copy_from_slice(&value.to_be_bytes())
    }

    pub fn get_protocol(&self) -> crate::InetProtocol {
        crate::InetProtocol::from(self.slice[9])
    }

    pub fn set_protocol(&mut self, protocol: crate::InetProtocol) {
        self.slice[9] = u8::from(protocol);
    }

    pub fn set_ecn(&mut self, ecn: u8) {
        self.slice[1] = 0b11 | self.slice[1];
    }

    pub fn set_dscp(&mut self, dscp: u8) {
        self.slice[1] = (dscp << 2) | self.slice[1]
    }

    pub fn get_ihl_u8(&self) -> u8 {
        self.slice[0] & 0xF
    }

    pub fn calc_size(&self) -> Result<IPv4Size, IhlError> {
        IPv4Size::try_from_ihl_u8(self.get_ihl_u8())
    }

    pub fn new(slice: &'pkt mut [u8]) -> Result<(Self, &'pkt mut [u8]), Error> {
        if slice.len() < Self::MIN_LEN {
            return Err(Error::InvalidSize(slice.len()));
        }

        let size = IPv4Size::try_from_ihl_u8(slice[0] & 0xF).map_err(|e| Error::InvalidIhl(e))?;

        if slice[0] >> 4 != 4 {
            return Err(Error::InvalidVersion(slice[0] >> 4));
        }

        if slice.len() < size as usize {
            return Err(Error::InvalidSizeForIhl(slice.len(), size));
        }

        let (slice, rem) = slice.split_at_mut(size as usize);
        Ok((Self { slice, size }, rem))
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[repr(usize)]
pub enum IPv4Size {
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

impl From<IhlError> for Error {
    fn from(value: IhlError) -> Self {
        Error::InvalidIhl(value)
    }
}

impl IPv4Size {
    pub fn try_from_ihl_u8(ihl: u8) -> Result<Self, IhlError> {
        Ok(match ihl {
            5 => IPv4Size::S20,
            6 => IPv4Size::S24,
            7 => IPv4Size::S28,
            8 => IPv4Size::S32,
            9 => IPv4Size::S36,
            10 => IPv4Size::S40,
            11 => IPv4Size::S44,
            12 => IPv4Size::S48,
            13 => IPv4Size::S52,
            14 => IPv4Size::S56,
            15 => IPv4Size::S60,
            x => {
                return Err(IhlError::InvalidIhl(x));
            }
        })
    }
}
