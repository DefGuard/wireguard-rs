use std::{
    mem::size_of,
    time::{Duration, SystemTime},
};

use super::{cast_bytes, cast_ref};

#[repr(C)]
struct TimeSpec {
    tv_sec: i64,
    tv_nsec: i64,
}

impl TimeSpec {
    fn duration(&self) -> Duration {
        Duration::from_secs(self.tv_sec as u64) + Duration::from_nanos(self.tv_nsec as u64)
    }
}

impl From<&TimeSpec> for SystemTime {
    fn from(time_spec: &TimeSpec) -> SystemTime {
        SystemTime::UNIX_EPOCH + time_spec.duration()
    }
}

impl From<&SystemTime> for TimeSpec {
    fn from(system_time: &SystemTime) -> Self {
        if let Ok(duration) = system_time.duration_since(SystemTime::UNIX_EPOCH) {
            Self {
                tv_sec: duration.as_secs() as i64,
                tv_nsec: duration.as_nanos() as i64,
            }
        } else {
            Self {
                tv_sec: 0,
                tv_nsec: 0,
            }
        }
    }
}

pub(super) fn pack_timespec(system_time: &SystemTime) -> Vec<u8> {
    let timespec: TimeSpec = system_time.into();
    let bytes = unsafe { cast_bytes(&timespec) };
    Vec::from(bytes)
}

pub(super) fn unpack_timespec(buf: &[u8]) -> Option<SystemTime> {
    const TS_SIZE: usize = size_of::<TimeSpec>();
    match buf.len() {
        TS_SIZE => {
            let ts = unsafe { cast_ref::<TimeSpec>(buf) };
            Some(ts.into())
        }
        _ => None,
    }
}
