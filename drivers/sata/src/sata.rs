#![no_std]
#![allow(non_snake_case, dead_code, unused_variables)] // Allow for c-style struct names and a conceptual implementation

extern crate alloc;

use core::{
    ptr::{self, volatile_read, volatile_write},
    mem,
};


/// Simple static buffer allocator placeholder. In a real no_std kernel, this
/// would use a physical page allocator to ensure DMA-safe memory.
mod q1_kernel_alloc {
    /// A conceptual page allocator that ensures pages are physically contiguous
    /// and accessible by the DMA engine.
    /// In a real driver, this would call into the Q1-kernel memory manager.
    pub fn alloc_dma_page(count: usize) -> *mut u8 {
        const PAGE_SIZE: usize = 4096;
        static mut HEAP: [u8; PAGE_SIZE * 16] = [0; PAGE_SIZE * 16];
        static mut OFFSET: usize = 0;
        unsafe {
            let offset = OFFSET;
            let total_size = count * PAGE_SIZE;
            if offset + total_size > HEAP.len() {
                // Return null pointer equivalent on failure
                return core::ptr::null_mut();
            }
            OFFSET += total_size;
            HEAP.as_mut_ptr().add(offset)
        }
    }
}

// --- AHCI Constants and Register Offsets -------------------------------------

/// SATA Command and Control Constants
const SECTOR_SIZE: usize = 512;
const AHCI_MAX_PORTS: usize = 32;
const AHCI_MAX_COMMANDS: usize = 32;
const HBA_GHC_OFFSET: usize = 0x04; // Global Host Control
const HBA_PI_OFFSET: usize = 0x0C; // Ports Implemented
const HBA_VS_OFFSET: usize = 0x10; // Version
const HBA_IS_OFFSET: usize = 0x08; // Interrupt Status
const PORT_REG_SIZE: usize = 0x80;
const HBA_PORT_START: usize = 0x100;

// HBA_GHC Register Bit Masks
const GHC_HR: u32 = 1 << 0;  // HBA Reset
const GHC_IE: u32 = 1 << 1;  // Interrupt Enable
const GHC_AE: u32 = 1 << 31; // AHCI Enable

// Port Register Offsets (relative to HBA_PORT_START + n*PORT_REG_SIZE)
const PORT_CLB_OFFSET: usize = 0x00; // Command List Base
const PORT_FB_OFFSET: usize = 0x08;  // FIS Base Address
const PORT_IS_OFFSET: usize = 0x10;  // Interrupt Status
const PORT_IE_OFFSET: usize = 0x14;  // Interrupt Enable
const PORT_CMD_OFFSET: usize = 0x18; // Command and Status
const PORT_SSTS_OFFSET: usize = 0x20; // Serial ATA Status

// PORT_CMD Register Bit Masks
const CMD_ST: u32 = 1 << 0;   // Start (Command List)
const CMD_FRE: u32 = 1 << 4;  // FIS Receive Enable
const CMD_CR: u32 = 1 << 15;  // Command List Running
const CMD_FR: u32 = 1 << 14;  // FIS Receive Running
const CMD_ICC_ACTIVE: u32 = 1; // Interface Communication Control: Active
const CMD_ICC_SLUMBER: u32 = 2; // Interface Communication Control: Slumber
const CMD_ICC_PARTIAL: u32 = 6; // Interface Communication Control: Partial

// HBA Port SATA Status (SSTS) fields
const SSTS_DET_PRESENT: u32 = 3; // Device Detection: Device present

// ATA Command FIS constants
const FIS_TYPE_H2D: u8 = 0x27; // Host to Device Register FIS
const ATA_CMD_READ_DMA_EXT: u8 = 0x25; // Read DMA EXT (48-bit LBA)
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35; // Write DMA EXT (48-bit LBA)
const ATA_CMD_IDENTIFY: u8 = 0xEC; // Identify Device

// --- Volatile Register Access ------------------------------------------------

/// A wrapper struct for a volatile, memory-mapped I/O register.
/// This is crucial for AHCI, as registers must not be optimized away by the compiler.
#[repr(transparent)]
pub struct VolatileRegister<T> {
    addr: *mut T,
}

impl<T> VolatileRegister<T> {
    const fn new(addr: *mut T) -> Self {
        Self { addr }
    }

    /// Reads the volatile register.
    pub fn read(&self) -> T {
        unsafe { volatile_read(self.addr) }
    }

    /// Writes a value to the volatile register.
    pub fn write(&mut self, value: T) {
        unsafe { volatile_write(self.addr, value) }
    }
}

// --- AHCI Memory Structures --------------------------------------------------

/// 1. HBA Memory/Register Block (HBA_MEM)
/// Base address: BAR for the AHCI controller (found via PCI).
#[repr(C)]
pub struct HbaMem {
    pub cap: VolatileRegister<u32>,      // 0x00
    pub ghc: VolatileRegister<u32>,      // 0x04
    pub is: VolatileRegister<u32>,       // 0x08
    pub pi: VolatileRegister<u32>,       // 0x0C
    pub vs: VolatileRegister<u32>,       // 0x10
    pub ccc_ctl: VolatileRegister<u32>,  // 0x14
    pub ccc_pts: VolatileRegister<u32>,  // 0x18
    pub em_loc: VolatileRegister<u32>,   // 0x1C
    pub em_ctl: VolatileRegister<u32>,   // 0x20
    pub cap2: VolatileRegister<u32>,     // 0x24
    pub bohc: VolatileRegister<u32>,     // 0x28
    _rsv: [u8; 0xA0 - 0x2C],             // Reserved
    pub vendor: [VolatileRegister<u32>; 24], // 0xA0..0xFC Vendor-specific
    pub ports: [HbaPort; AHCI_MAX_PORTS], // 0x100..0x1700 Port Register Space
}

/// 2. HBA Port Register Block (HBA_Px)
#[repr(C)]
pub struct HbaPort {
    pub clb: VolatileRegister<u32>,      // 0x00 Command List Base Address
    pub clbu: VolatileRegister<u32>,     // 0x04 Command List Base Address Upper
    pub fb: VolatileRegister<u32>,       // 0x08 FIS Base Address
    pub fbu: VolatileRegister<u32>,      // 0x0C FIS Base Address Upper
    pub is: VolatileRegister<u32>,       // 0x10 Interrupt Status
    pub ie: VolatileRegister<u32>,       // 0x14 Interrupt Enable
    pub cmd: VolatileRegister<u32>,      // 0x18 Command and Status
    _rsv: VolatileRegister<u32>,         // 0x1C
    pub tfd: VolatileRegister<u32>,      // 0x20 Task File Data
    pub ssts: VolatileRegister<u32>,     // 0x24 SATA Status
    pub sctl: VolatileRegister<u32>,     // 0x28 SATA Control
    pub serr: VolatileRegister<u32>,     // 0x2C SATA Error
    pub sact: VolatileRegister<u32>,     // 0x30 SATA Active
    pub ci: VolatileRegister<u32>,       // 0x34 Command Issue
    pub saz: VolatileRegister<u32>,      // 0x38 SATA Notification
    pub ipm: VolatileRegister<u32>,      // 0x3C Interrupt Pending Mask
    pub dmps: VolatileRegister<u32>,     // 0x40 Device Mechanical Presence Status
    _rsv1: [VolatileRegister<u32>; 4],   // 0x44..0x50
    pub vendor: [VolatileRegister<u32>; 4], // 0x54..0x80 Vendor specific
}

/// 3. Command List Header (CLB) - 32 entries per port
#[repr(C, align(1024))] // Must be 1K-byte aligned
pub struct HbaCmdHeader {
    // DW0
    pub cfl: u8, // Command FIS length (in DWORDS)
    pub a: u8,   // ATAPI (0=ATA, 1=ATAPI)
    pub p: u8,   // Protocol (0=PIO, 1=DMA, 2=BIST, 3=PMC, 4=Dev Reset)
    pub r: u8,   // Reserved (must be 0)
    pub prdtl: u16, // Physical Region Descriptor Table Length
    pub prdtrb: u16, // PRD Table Byte Count (transferred bytes)
    // DW1
    pub cdb_len: u16, // Command Descriptor Block Length (ATAPI)
    pub _rsv1: u16,
    // DW2
    pub ctba: u32, // Command Table Base Address
    // DW3
    pub ctbau: u32, // Command Table Base Address Upper 32-bits
    // DW4-7
    pub _rsv2: [u32; 4],
}

/// 4. Command Table (CTBA)
/// For a 32-command queue, the CTBA is 256 bytes (0x100)
#[repr(C, align(128))] // Must be 128-byte aligned
pub struct HbaCmdTable {
    // 0x00: Command FIS - 64 bytes
    pub cfis: [u8; 64],
    // 0x40: ATAPI Command - 16 bytes
    pub acmd: [u8; 16],
    // 0x50: Reserved - 48 bytes
    pub _rsv: [u8; 48],
    // 0x80: Physical Region Descriptor Table (PRDT) - 1 entry
    // NOTE: This array size will be dynamic in a real driver based on `prdtl`.
    // We define a single entry for simplicity, which is enough for one sector.
    pub prdt_entry: HbaPrdtEntry,
}

/// 5. Physical Region Descriptor Table Entry (PRDT)
#[repr(C)]
pub struct HbaPrdtEntry {
    pub dba: u32,  // Data Base Address
    pub dbau: u32, // Data Base Address Upper
    pub _rsv: u32,
    pub dbc: u32, // Data Byte Count (0-based, so N-1 bytes)
}

/// 6. Received FIS Structure (FB)
#[repr(C, align(256))] // Must be 256-byte aligned
pub struct HbaReceivedFis {
    pub dsfis: [u8; 256], // DMA Setup FIS
    pub psfis: [u8; 256], // PIO Setup FIS
    pub r_fis: [u8; 256], // Register FIS
    pub sdbfis: [u8; 256], // Set Device Bit FIS
    pub ufis: [u8; 256],  // Unknown FIS
    _rsv: [u8; 256],
}

// --- AHCI Driver Implementation ----------------------------------------------

/// Represents a single SATA/AHCI port on the Host Bus Adapter.
pub struct SataPort<'a> {
    hba_mem: &'a mut HbaMem,
    port_reg: *mut HbaPort,
    port_num: u8,
    cmd_list: *mut HbaCmdHeader,
    rfis: *mut HbaReceivedFis,
}

impl SataPort<'_> {
    /// Resets the Port and enables command list processing and FIS reception.
    fn port_start(&mut self) {
        let port = unsafe { &mut *self.port_reg };

        // 1. Clear CR (Command List Running) and FR (FIS Receive Running)
        // This is done by first clearing ST and FRE bits, and waiting for CR/FR to clear.
        port.cmd.write(port.cmd.read() & !(CMD_ST | CMD_FRE));
        
        // Wait for Command List Running (CR) and FIS Receive Running (FR) to clear
        // In a real driver, this would be a timed loop.
        while (port.cmd.read() & (CMD_CR | CMD_FR)) != 0 {
            // Placeholder: yield to Q1-kernel scheduler or busy-wait
            // core::hint::spin_loop(); 
        }

        // 2. Clear Port Interrupt Status
        port.is.write(0xFFFFFFFF);

        // 3. Set FIS Receive Enable (FRE) and Command List Start (ST)
        port.cmd.write(port.cmd.read() | CMD_FRE);
        
        // Wait for FR to set
        while (port.cmd.read() & CMD_FR) == 0 {
            // core::hint::spin_loop();
        }

        port.cmd.write(port.cmd.read() | CMD_ST);
    }

    /// Initializes a Command Header for an ATA command.
    fn init_cmd_header(&mut self, slot_id: usize, is_write: bool, sector_count: u16) {
        let hdr = unsafe { &mut *self.cmd_list.add(slot_id) };
        
        // Command FIS Length: 5 DWORDS (20 bytes)
        hdr.cfl = mem::size_of::<[u32; 5]>() as u8 / mem::size_of::<u32>() as u8;
        
        // A=0 (ATA), P=1 (DMA), PRDTL=1 (one PRDT entry)
        hdr.a = 0;
        hdr.p = 1;
        hdr.prdtl = 1;

        // Reset all other fields
        hdr.prdtrb = 0;
        hdr.ctba = 0;
        hdr.ctbau = 0;
        hdr._rsv2 = [0; 4];
    }

    /// Builds a Host-to-Device (H2D) Register FIS for the given slot.
    fn build_h2d_fis(&mut self, slot_id: usize, lba: u64, sector_count: u16, cmd: u8) -> *mut HbaCmdTable {
        let hdr = unsafe { &mut *self.cmd_list.add(slot_id) };
        let cmd_table_addr = hdr.ctba as usize | ((hdr.ctbau as usize) << 32);
        let cmd_table = cmd_table_addr as *mut HbaCmdTable;
        let cfis = unsafe { &mut *cmd_table }.cfis;
        
        // 1. Build the CFIS (Command FIS)
        cfis[0] = FIS_TYPE_H2D; // FIS Type: Host to Device Register FIS
        cfis[1] = 1 << 7;       // C bit (Command): 1
        cfis[2] = cmd;          // Command (e.g., Read DMA EXT)

        // LBA and Sector Count for 48-bit LBA (6 DWORDS, 24 bytes)
        // 48-bit LBA (sectors per transfer: 65536 max)
        cfis[4] = sector_count as u8; // Sector Count LSB
        cfis[5] = (sector_count >> 8) as u8; // Sector Count MSB
        
        // LBA low (bytes 0-7)
        cfis[6] = lba as u8;
        cfis[7] = (lba >> 8) as u8;
        cfis[8] = (lba >> 16) as u8;
        
        // LBA mid (bytes 8-15)
        cfis[10] = (lba >> 24) as u8;
        cfis[11] = (lba >> 32) as u8;
        cfis[12] = (lba >> 40) as u8;
        
        // Device Register: LBA Mode, DEV=0 (master/single drive)
        cfis[13] = 0x40;

        // 2. Update Command Table Base Address (CTBA)
        // In a real implementation, we would allocate a Command Table and set CTBA/CTBAU.
        // For this conceptual code, we assume `cmd_table_addr` is already the physical address.

        cmd_table
    }

    /// Sends a command and waits for completion.
    /// This is a simplified, synchronous blocking call.
    fn execute_command(&mut self, slot_id: usize) -> Result<(), &str> {
        let port = unsafe { &mut *self.port_reg };

        // 1. Issue command by setting the bit in Command Issue (CI) register
        port.ci.write(1 << slot_id);

        // 2. Wait for completion (CI bit to clear)
        // In a real driver, this would use an interrupt.
        let mut timeout = 0;
        while (port.ci.read() & (1 << slot_id)) != 0 {
            timeout += 1;
            if timeout > 1_000_000 {
                return Err("Command timeout");
            }
            // core::hint::spin_loop();
        }

        // 3. Check for errors (Task File Data, TFD)
        let tfd = port.tfd.read();
        if (tfd & 0x100) != 0 { // ERR bit in Task File Data
            return Err("ATA Command failed (TFD error)");
        }

        Ok(())
    }

    /// Reads `sector_count` sectors from LBA `start_lba` into `buffer_addr`.
    pub fn read_sectors(&mut self, start_lba: u64, sector_count: u16, buffer_addr: *mut u8) -> Result<(), &str> {
        if sector_count == 0 { return Ok(()); }
        let slot = 0; // Use command slot 0 for simplicity

        // 1. Initialize Command Header and Command Table/PRDT
        self.init_cmd_header(slot, false, sector_count);

        let hdr = unsafe { &mut *self.cmd_list.add(slot) };
        let cmd_table_addr = hdr.ctba as usize | ((hdr.ctbau as usize) << 32);
        let cmd_table = cmd_table_addr as *mut HbaCmdTable;
        let prdt = unsafe { &mut (*cmd_table).prdt_entry };
        
        // Configure PRDT for the transfer
        prdt.dba = buffer_addr as u32; // Assuming 32-bit DMA for simplicity
        prdt.dbau = (buffer_addr as usize >> 32) as u32;
        // Data Byte Count: (N-1) bytes. Total bytes = sector_count * SECTOR_SIZE
        prdt.dbc = (sector_count as u32 * SECTOR_SIZE as u32) - 1;
        
        // 2. Build the Command FIS (Read DMA EXT)
        self.build_h2d_fis(slot, start_lba, sector_count, ATA_CMD_READ_DMA_EXT);

        // 3. Execute the command
        self.execute_command(slot)
    }

    /// Conceptual write function. Structure is similar to read.
    pub fn write_sectors(&mut self, start_lba: u64, sector_count: u16, buffer_addr: *const u8) -> Result<(), &str> {
        if sector_count == 0 { return Ok(()); }
        let slot = 0; // Use command slot 0 for simplicity

        // ... Similar steps as `read_sectors` ...
        self.init_cmd_header(slot, true, sector_count);

        let hdr = unsafe { &mut *self.cmd_list.add(slot) };
        let cmd_table_addr = hdr.ctba as usize | ((hdr.ctbau as usize) << 32);
        let cmd_table = cmd_table_addr as *mut HbaCmdTable;
        let prdt = unsafe { &mut (*cmd_table).prdt_entry };
        
        prdt.dba = buffer_addr as u32;
        prdt.dbau = (buffer_addr as usize >> 32) as u32;
        prdt.dbc = (sector_count as u32 * SECTOR_SIZE as u32) - 1;
        
        self.build_h2d_fis(slot, start_lba, sector_count, ATA_CMD_WRITE_DMA_EXT);

        self.execute_command(slot)
    }
}

/// The main driver structure for the AHCI HBA.
pub struct SataDriver {
    hba_mem: *mut HbaMem,
    ports: [Option<SataPort<'static>>; AHCI_MAX_PORTS],
}

impl SataDriver {
    /// Creates a new, uninitialized driver instance.
    pub const fn new() -> Self {
        const NONE: Option<SataPort<'static>> = None;
        SataDriver {
            hba_mem: ptr::null_mut(),
            ports: [NONE; AHCI_MAX_PORTS],
        }
    }

    /// 1. Global HBA Initialization: Reset, Enable AHCI mode, Enable Interrupts.
    /// `hba_addr` is the physical base address (MMIO) of the AHCI controller.
    pub fn init(&mut self, hba_addr: u64) -> Result<(), &str> {
        self.hba_mem = hba_addr as *mut HbaMem;
        let hba = unsafe { &mut *self.hba_mem };

        // 1. Reset the HBA
        hba.ghc.write(hba.ghc.read() | GHC_HR);
        // Wait for reset to complete
        let mut timeout = 0;
        while (hba.ghc.read() & GHC_HR) != 0 {
            timeout += 1;
            if timeout > 1_000_000 { return Err("HBA Reset timeout"); }
            // core::hint::spin_loop();
        }

        // 2. Enable AHCI mode and Interrupts
        hba.ghc.write(hba.ghc.read() | GHC_AE | GHC_IE);

        // 3. Find implemented ports
        let pi = hba.pi.read();
        
        for i in 0..AHCI_MAX_PORTS {
            if (pi & (1 << i)) != 0 {
                if let Err(e) = self.init_port(i as u8) {
                    // Log error but continue to next port
                    // println!("Port {} init failed: {}", i, e);
                }
            }
        }

        Ok(())
    }

    /// 2. Port Initialization: Configure command list, FIS, and start port.
    fn init_port(&mut self, port_num: u8) -> Result<(), &str> {
        let port_idx = port_num as usize;
        let hba = unsafe { &mut *self.hba_mem };
        let port_reg = &mut hba.ports[port_idx] as *mut HbaPort;
        let port = unsafe { &mut *port_reg };

        // Check if a device is attached
        if (port.ssts.read() >> 0 & 0xF) != SSTS_DET_PRESENT {
            return Err("No device attached to port");
        }
        
        // Stop the port first (clear ST and FRE)
        port.cmd.write(port.cmd.read() & !(CMD_ST | CMD_FRE));

        // 1. Allocate Command List (CLB) - 1KB aligned
        let clb_ptr = q1_kernel_alloc::alloc_dma_page(1);
        if clb_ptr.is_null() { return Err("Failed to allocate CLB"); }

        // Set CLB/CLBU (assuming 64-bit address)
        port.clb.write(clb_ptr as u32);
        port.clbu.write((clb_ptr as usize >> 32) as u32);
        
        // 2. Allocate Received FIS (FB) - 256 byte aligned
        let rfis_ptr = q1_kernel_alloc::alloc_dma_page(1);
        if rfis_ptr.is_null() { return Err("Failed to allocate RFIS"); }
        // Set FB/FBU
        port.fb.write(rfis_ptr as u32);
        port.fbu.write((rfis_ptr as usize >> 32) as u32);
        
        // 3. Allocate Command Tables (CTBA) for all command headers
        // Each command header points to its own Command Table.
        // For simplicity, we allocate a contiguous block and assign addresses.
        let ct_block = q1_kernel_alloc::alloc_dma_page(AHCI_MAX_COMMANDS);
        if ct_block.is_null() { return Err("Failed to allocate Command Tables"); }

        for i in 0..AHCI_MAX_COMMANDS {
            let hdr = unsafe { &mut *(clb_ptr as *mut HbaCmdHeader).add(i) };
            let ct_addr = unsafe { ct_block.add(i * mem::size_of::<HbaCmdTable>()) };
            
            // Set CTBA/CTBAU (physical address of the Command Table)
            hdr.ctba = ct_addr as u32;
            hdr.ctbau = (ct_addr as usize >> 32) as u32;
        }

        // 4. Create and store the SataPort instance
        let mut driver_port = SataPort {
            hba_mem: unsafe { &mut *self.hba_mem },
            port_reg,
            port_num,
            cmd_list: clb_ptr as *mut HbaCmdHeader,
            rfis: rfis_ptr as *mut HbaReceivedFis,
        };

        // 5. Start the port
        driver_port.port_start();
        
        // 6. Run IDENTIFY DEVICE command (omitting the actual parsing)
        // A successful IDENTIFY command confirms a device is ready.
        let identify_buffer = q1_kernel_alloc::alloc_dma_page(1);
        match driver_port.identify_device(identify_buffer) {
            Ok(_) => {
                // If IDENTIFY succeeds, the port is ready to use.
                // We use a safe-but-leaky method to store the port for simplicity.
                let boxed_port = alloc::boxed::Box::new(driver_port);
                let static_port_ref = unsafe { mem::transmute::<alloc::boxed::Box<SataPort<'_>>, &'static mut SataPort<'static>>(boxed_port) };
                self.ports[port_idx] = Some(static_port_ref);
                Ok(())
            },
            Err(e) => Err("Identify device failed"),
        }
    }

    /// Conceptual driver entry point for the kernel to read sectors.
    pub fn read(&mut self, port_num: u8, lba: u64, count: u16, buffer: *mut u8) -> Result<(), &str> {
        let port_idx = port_num as usize;
        if port_idx >= AHCI_MAX_PORTS {
            return Err("Invalid port number");
        }

        match self.ports[port_idx].as_mut() {
            Some(port) => port.read_sectors(lba, count, buffer),
            None => Err("Port not initialized or device not present"),
        }
    }
}

// --- AHCI Driver Extensions (Part of SataPort) -------------------------------

impl SataPort<'_> {
    /// Executes the ATA IDENTIFY DEVICE command.
    fn identify_device(&mut self, buffer_addr: *mut u8) -> Result<(), &str> {
        let slot = 0;
        let sector_count = 1; // 1 sector (512 bytes)

        // 1. Initialize Command Header
        self.init_cmd_header(slot, false, sector_count);

        let hdr = unsafe { &mut *self.cmd_list.add(slot) };
        let cmd_table_addr = hdr.ctba as usize | ((hdr.ctbau as usize) << 32);
        let cmd_table = cmd_table_addr as *mut HbaCmdTable;
        let prdt = unsafe { &mut (*cmd_table).prdt_entry };
        
        // Configure PRDT for 512-byte transfer
        prdt.dba = buffer_addr as u32;
        prdt.dbau = (buffer_addr as usize >> 32) as u32;
        prdt.dbc = (sector_count as u32 * SECTOR_SIZE as u32) - 1;
        
        // 2. Build the Command FIS (IDENTIFY DEVICE)
        self.build_h2d_fis(slot, 0, 0, ATA_CMD_IDENTIFY);
        
        // Set the transfer direction (B/C bits in header) for identify
        // For IDENTIFY, this is a PIO Setup FIS data transfer *from* the device,
        // but for simplicity in this conceptual DMA-centric driver, we use the
        // DMA logic and rely on the controller handling IDENTIFY correctly.
        
        // 3. Execute the command
        self.execute_command(slot)
    }

    /// Conceptual Interrupt Service Routine (ISR) entry point for a single port.
    /// In Q1-kernel's 'segmented interrupt architecture', this would likely be a 
    /// fast 'fiber' executed right after the hardware interrupt.
    pub fn handle_interrupt(&mut self) {
        let port = unsafe { &mut *self.port_reg };
        let is_status = port.is.read();

        // 1. Process received FISes/Errors
        if is_status != 0 {
            // Check for DFE (Device Fatal Error), PCE (PIO Setup FIS Error), etc.
            
            // Log/handle any errors (omitted for brevity)

            // 2. Acknowledge and clear all interrupts
            port.is.write(is_status);
        }

        // 3. Check Command Issue (CI) register for completed commands
        // In a real NCQ driver, this would check which bits cleared
        // in CI (due to completion) and notify the waiting command queue.
        
        // For this simple blocking driver, all work is done in `execute_command`.
        
        // 4. Acknowledge HBA level interrupt
        // This is done by the main SataDriver ISR (omitted).
    }
}

// --- Driver Interface (Conceptual Kernel Entry) ------------------------------

static mut AHCI_DRIVER: SataDriver = SataDriver::new();

/// The public entry point for the Q1-kernel to initialize the SATA driver.
/// This function is typically called by the PCI enumeration code.
///
/// # Safety
/// This function performs raw memory-mapped I/O and modifies global state.
/// It must be called once by the kernel's initialization code.
#[no_mangle]
pub unsafe extern "C" fn q1_sata_driver_init(hba_base_addr: u64) -> bool {
    // Requires a global allocator for `alloc::boxed::Box::new` in init_port
    // For a `no_std` crate with `alloc`, the kernel must provide the allocator.
    // For this conceptual example, we rely on the kernel-provided `q1_kernel_alloc`.
    
    match AHCI_DRIVER.init(hba_base_addr) {
        Ok(_) => true,
        Err(_) => false, // Initialization failed
    }
}

/// The public entry point for the Q1-kernel to request a disk read.
///
/// # Safety
/// `buffer` must be a valid, DMA-accessible memory address.
#[no_mangle]
pub unsafe extern "C" fn q1_sata_read_sectors(
    port: u8, 
    lba: u64, 
    count: u16, 
    buffer: *mut u8
) -> bool {
    match AHCI_DRIVER.read(port, lba, count, buffer) {
        Ok(_) => true,
        Err(_) => false,
    }
}


/// The required panic handler for a `no_std` environment.
/// In a real OS, this would halt the CPU or reboot.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // In a Q1-kernel RTOS, this would signal a catastrophic failure.
    loop {}
}

