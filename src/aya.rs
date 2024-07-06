use aya_ebpf_bindings::bindings::xdp_action;

pub struct BoundsError;

#[macro_export]
macro_rules! bounds {
    ($ctx:expr, $size:expr) => {
        if ($ctx.data() + $size > $ctx.data_end()) {
            Err($crate::aya::BoundsError)
        } else {
            Ok(())
        }
    };
}

pub trait XdpErr<T> {
    fn or_drop(self) -> Result<T, u32>
    where
        T: core::marker::Sized;
    fn or_pass(self) -> Result<T, u32>
    where
        T: core::marker::Sized;
    fn or_abort(self) -> Result<T, u32>
    where
        T: core::marker::Sized;
}

impl<T, E> XdpErr<T> for Result<T, E> {
    fn or_drop(self) -> Result<T, u32>
    where
        T: core::marker::Sized,
    {
        self.map_err(|_| xdp_action::XDP_DROP)
    }

    fn or_pass(self) -> Result<T, u32>
    where
        T: core::marker::Sized,
    {
        self.map_err(|_| xdp_action::XDP_PASS)
    }

    fn or_abort(self) -> Result<T, u32>
    where
        T: core::marker::Sized,
    {
        self.map_err(|_| xdp_action::XDP_ABORTED)
    }
}
