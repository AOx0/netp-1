pub struct Ethernet<'pkt> {
    slice: &'pkt mut [u8],
    size: EtherSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EtherType {
    IPV4 = 0x0800,
    IPV6 = 0x86dd,
    ARP = 0x0806,
    WAKE_ON_LAN = 0x0842,
    VLAN_TAGGED_FRAME = 0x8100,
    PROVIDER_BRIDGING = 0x88A8,
    VLAN_DOUBLE_TAGGED_FRAME = 0x9100,
    OTHER(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(usize)]
pub enum EtherSize {
    S18 = Ethernet::MAX_LEN,
    S16 = Ethernet::MAX_LEN - 2,
    S14 = Ethernet::MIN_LEN,
}

impl From<EtherType> for u16 {
    fn from(value: EtherType) -> Self {
        match value {
            EtherType::IPV4 => 0x0800,
            EtherType::IPV6 => 0x86dd,
            EtherType::ARP => 0x0806,
            EtherType::WAKE_ON_LAN => 0x0842,
            EtherType::VLAN_TAGGED_FRAME => 0x8100,
            EtherType::PROVIDER_BRIDGING => 0x88A8,
            EtherType::VLAN_DOUBLE_TAGGED_FRAME => 0x9100,
            EtherType::OTHER(v) => v,
        }
    }
}

impl From<[u8; 2]> for EtherType {
    fn from(value: [u8; 2]) -> Self {
        let num = u16::from_be_bytes(value);
        EtherType::from(num)
    }
}

impl TryFrom<&[u8]> for EtherType {
    type Error = ();
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 2 {
            return Err(());
        }

        let array = *value.first_chunk::<2>().unwrap();
        Ok(EtherType::from(array))
    }
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => Self::IPV4,
            0x86dd => Self::IPV6,
            0x0806 => Self::ARP,
            0x0842 => Self::WAKE_ON_LAN,
            0x8100 => Self::VLAN_TAGGED_FRAME,
            0x88A8 => Self::PROVIDER_BRIDGING,
            0x9100 => Self::VLAN_DOUBLE_TAGGED_FRAME,
            x => Self::OTHER(x),
        }
    }
}

pub enum Error {
    WrongSize(usize),
    WrongSizeForType(EtherType, usize),
}

impl<'pkt> Ethernet<'pkt> {
    pub const MIN_LEN: usize = 14;
    pub const MAX_LEN: usize = 18;

    pub fn get_ethertype(&'pkt self) -> EtherType {
        EtherType::from(*self.slice[12..16].first_chunk::<2>().unwrap())
    }

    pub fn set_destination(&mut self, new_dest: &[u8; 6]) {
        self.slice[6..12].copy_from_slice(new_dest);
    }

    pub fn get_destination(&self) -> &[u8; 6] {
        self.slice[6..12].try_into().unwrap()
    }

    pub fn get_size_usize(&self) -> usize {
        match self.size {
            EtherSize::S18 => 18,
            EtherSize::S16 => 16,
            EtherSize::S14 => 14,
        }
    }

    pub fn get_size(&self) -> EtherSize {
        self.size
    }

    pub fn set_source(&mut self, new_dest: &[u8; 6]) {
        self.slice[0..6].copy_from_slice(new_dest);
    }

    pub fn get_source(&self) -> &[u8; 6] {
        self.slice[0..6].try_into().unwrap()
    }

    pub fn new_min(slice: &'pkt mut [u8]) -> (Self, &'pkt mut [u8]) {
        let (parsed, rem) = slice.split_at_mut(Self::MIN_LEN);
        (
            Self {
                slice: parsed,
                size: EtherSize::S14,
            },
            rem,
        )
    }

    pub fn new(slice: &'pkt mut [u8]) -> Result<(Self, &'pkt mut [u8]), Error> {
        if slice.len() < Self::MIN_LEN {
            return Err(Error::WrongSize(slice.len()));
        }

        let size = match EtherType::from(*slice[12..14].first_chunk::<2>().unwrap()) {
            EtherType::VLAN_DOUBLE_TAGGED_FRAME if slice.len() >= Self::MAX_LEN => EtherSize::S18,
            EtherType::VLAN_TAGGED_FRAME if slice.len() >= Self::MIN_LEN + 2 => EtherSize::S16,
            EtherType::OTHER(_) if slice.len() >= Self::MIN_LEN => EtherSize::S14,
            _ if slice.len() >= Self::MIN_LEN => EtherSize::S14,
            x => return Err(Error::WrongSizeForType(x, slice.len())),
        };

        let (parsed, rem) = slice.split_at_mut(size as usize);
        Ok((
            Self {
                slice: parsed,
                size,
            },
            rem,
        ))
    }
}
