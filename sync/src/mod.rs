use super::{AtomicLock, AttemptStatus};
use crate::platform::types::*;
use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicI32 as AtomicInt, Ordering},
};

pub(crate) const UNLOCKED: c_int = 0;
pub(crate) const LOCKED: c_int = 1;
pub(crate) const WAITING: c_int = 2;

pub struct Mutex<T> {
    pub(crate) lock: AtomicLock,
    content: UnsafeCell<T>,
}
unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}
use spin::Once;

use crate::mem::paging::VirtAddr;
use crate::utils::sync::{Mutex, MutexGuard};

use self::hpet::Hpet;
use self::madt::Madt;
use self::mcfg::Mcfg;
use self::sdt::Sdt;

pub mod aml;
pub mod fadt;
pub mod hpet;
pub mod madt;
pub mod mcfg;
pub mod rsdp;
pub mod sdt;

enum AcpiHeader {
    Rsdt(&'static rsdp::Rsdt<u32>),
    Xsdt(&'static rsdp::Rsdt<u64>),
}

pub struct AcpiTable {
    header: AcpiHeader,
}

impl AcpiTable {
    fn new(rsdp_address: VirtAddr) -> Self {
        match rsdp::find_rsdt_address(rsdp_address) {
            rsdp::RsdtAddress::Xsdt(xsdt_addr) => {
                let xsdt = rsdp::Rsdt::<u64>::new(xsdt_addr);
                let header = AcpiHeader::Xsdt(xsdt);

                log::debug!("found XSDT at {:#x}", xsdt_addr);

                Self { header }
            }

            rsdp::RsdtAddress::Rsdt(rsdt_addr) => {
                let rsdt = rsdp::Rsdt::<u32>::new(rsdt_addr);
                let header = AcpiHeader::Rsdt(rsdt);

                log::debug!("found RSDT at {:#x}", rsdt_addr);

                Self { header }
            }
        }
    }

    /// Lookup ACPI table entry with the provided signature.
    pub fn lookup_entry(&self, signature: &str, index: usize) -> Option<&'static Sdt> {
        match self.header {
            AcpiHeader::Rsdt(rsdt) => rsdt.lookup_entry(signature, index),
            AcpiHeader::Xsdt(xsdt) => xsdt.lookup_entry(signature, index),
        }
    }

    pub fn revision(&self) -> u8 {
        match self.header {
            AcpiHeader::Rsdt(rsdt) => rsdt.header.revision,
            AcpiHeader::Xsdt(xsdt) => xsdt.header.revision,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct GenericAddressStructure {
    pub address_space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
}

static ACPI_TABLE: Once<Mutex<AcpiTable>> = Once::new();

pub fn get_acpi_table() -> MutexGuard<'static, AcpiTable> {
    ACPI_TABLE.get().unwrap().lock()
}

/// Initialize the ACPI tables.
pub fn init(rsdp_address: VirtAddr) {
    let acpi_table = AcpiTable::new(rsdp_address);

    ACPI_TABLE.call_once(|| Mutex::new(acpi_table));

    let acpi_table = get_acpi_table();

    macro init_table($sig:path => $ty:ty) {
        if let Some(table) = acpi_table.lookup_entry($sig, 0) {
            <$ty>::new(table);
        }
    }

    if let Some(header) = acpi_table.lookup_entry(mcfg::SIGNATURE, 0) {
        unsafe {
            let mcfg: &'static Mcfg = header.as_ref();
            mcfg.init();
        }
    }

    if let Some(header) = acpi_table.lookup_entry(madt::SIGNATURE, 0) {
        unsafe {
            // Not a valid MADT table without the local apic address and the flags.
            if header.data_len() < 8 {
                log::warn!(
                    "assertion failed: header.data_len() < 8 => {}",
                    header.data_len()
                );
            } else {
                let madt: &'static Madt = header.as_ref();
                madt.init();
            }
        }
    }

    init_table!(hpet::SIGNATURE => Hpet);
}
pub(crate) unsafe fn manual_try_lock_generic(word: &AtomicInt) -> bool {
    word.compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
}
pub(crate) unsafe fn manual_lock_generic(word: &AtomicInt) {
    crate::sync::wait_until_generic(
        word,
        |lock| {
            lock.compare_exchange_weak(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
                .map(|_| AttemptStatus::Desired)
                .unwrap_or_else(|e| match e {
                    WAITING => AttemptStatus::Waiting,
                    _ => AttemptStatus::Other,
                })
        },
        |lock| match lock
            // TODO: Ordering
            .compare_exchange_weak(LOCKED, WAITING, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|e| e)
        {
            UNLOCKED => AttemptStatus::Desired,
            WAITING => AttemptStatus::Waiting,
            _ => AttemptStatus::Other,
        },
        WAITING,
    );
}
pub(crate) unsafe fn manual_unlock_generic(word: &AtomicInt) {
    if word.swap(UNLOCKED, Ordering::Release) == WAITING {
        crate::sync::futex_wake(word, i32::MAX);
    }
}

impl<T> Mutex<T> {
    /// Create a new mutex
    pub const fn new(content: T) -> Self {
        Self {
            lock: AtomicLock::new(UNLOCKED),
            content: UnsafeCell::new(content),
        }
    }
    /// Create a new mutex that is already locked. This is a more
    /// efficient way to do the following:
    /// ```rust
    /// let mut mutex = Mutex::new(());
    /// mutex.manual_lock();
    /// ```
    pub unsafe fn locked(content: T) -> Self {
        Self {
            lock: AtomicLock::new(LOCKED),
            content: UnsafeCell::new(content),
        }
    }

    /// Tries to lock the mutex, fails if it's already locked. Manual means
    /// it's up to you to unlock it after mutex. Returns the last atomic value
    /// on failure. You should probably not worry about this, it's used for
    /// internal optimizations.
    pub unsafe fn manual_try_lock(&self) -> Result<&mut T, c_int> {
        if unsafe { manual_try_lock_generic(&self.lock) } {
            Ok(unsafe { &mut *self.content.get() })
        } else {
            Err(0)
        }
    }
    /// Lock the mutex, returning the inner content. After doing this, it's
    /// your responsibility to unlock it after usage. Mostly useful for FFI:
    /// Prefer normal .lock() where possible.
    pub unsafe fn manual_lock(&self) -> &mut T {
        unsafe { manual_lock_generic(&self.lock) };
        unsafe { &mut *self.content.get() }
    }
    /// Unlock the mutex, if it's locked.
    pub unsafe fn manual_unlock(&self) {
        unsafe { manual_unlock_generic(&self.lock) }
    }
    pub fn as_ptr(&self) -> *mut T {
        self.content.get()
    }

    /// Tries to lock the mutex and returns a guard that automatically unlocks
    /// the mutex when it falls out of scope.
    pub fn try_lock(&self) -> Option<MutexGuard<T>> {
        unsafe {
            self.manual_try_lock().ok().map(|content| MutexGuard {
                mutex: self,
                content,
            })
        }
    }
    /// Locks the mutex and returns a guard that automatically unlocks the
    /// mutex when it falls out of scope.
    pub fn lock(&self) -> MutexGuard<T> {
        MutexGuard {
            mutex: self,
            content: unsafe { self.manual_lock() },
        }
    }
}

pub struct MutexGuard<'a, T: 'a> {
    pub(crate) mutex: &'a Mutex<T>,
    content: &'a mut T,
}
impl<'a, T> Deref for MutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.content
    }
}
impl<'a, T> DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.content
    }
}
impl<'a, T> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        unsafe {
            self.mutex.manual_unlock();
        }
    }
}

#[macro_use]
pub mod cap;
const KERNEL_BASE: u64 = 0xFFFFFFFF80000000;

extern {
    static kernel_end: u64;
}

fn kernel_start_paddr() -> PAddr {
    PAddr::from(0x100000: usize)
}

fn kernel_start_vaddr() -> VAddr {
    unsafe { kernel_paddr_to_vaddr(kernel_start_paddr()) }
}

fn kernel_end_paddr() -> PAddr {
    unsafe { PAddr::from((&kernel_end as *const _) as u64 - KERNEL_BASE) }
}

#[allow(dead_code)]
fn kernel_end_vaddr() -> VAddr {
    unsafe { kernel_paddr_to_vaddr(kernel_end_paddr()) }
}

unsafe fn kernel_paddr_to_vaddr(addr: PAddr) -> VAddr {
    VAddr::from(addr.into(): u64 + KERNEL_BASE)
}


#[cfg(any(target_arch = "x86_64"))]
pub unsafe fn outportb(port: u16, val: u8)
{
    asm!("outb %al, %dx" : : "{dx}"(port), "{al}"(val));
}

#[cfg(any(target_arch = "x86_64"))]
pub unsafe fn inportb(port: u16) -> u8
{
    let ret: u8;
    asm!("inb %dx, %al" : "={ax}"(ret): "{dx}"(port));
    ret
}

#[cfg(any(target_arch = "x86_64"))]
pub unsafe fn io_wait() {
    outportb(0x80, 0)
}

pub fn enable_timer() {
    interrupt::LOCAL_APIC.lock().enable_timer();
}

// Public interfaces
pub use self::paging::{MemoryObject};
pub use self::interrupt::{enable_interrupt, disable_interrupt, set_interrupt_handler,
                          Exception, TaskRuntime};
pub use self::init::{InitInfo};
// pub use self::cap::{ArchCap, PageHalf, PageFull};
pub use self::addr::{PAddr, VAddr};

// pub type TopPageTableHalf = self::cap::PML4Half;
// pub type TopPageTableFull = self::cap::PML4Full;
