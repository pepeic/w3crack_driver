pub const HASH_LOOPS_SHA256: u32 = 923;
pub const HASH_LOOPS_SHA512: u32 = 250;

#[repr(align(4))]
#[derive(Clone, Copy)]
pub struct PBKDF2_SHA256_Salt
{
	pub length: u32,
	
	//salt size for the kernel being set dynamically on compile time
	pub salt: [u8; 1],
}

#[repr(align(4))]
#[derive(Clone, Copy)]
pub struct PBKDF2_SHA256_Config
{
	pub rounds: u32,
	pub skip_bytes: u32,
	pub outlen: u32,
}

#[repr(align(4))]
#[derive(Clone, Copy)]
pub struct PBKDF2_SHA256_State
{
	pub ipad: [u32; 8],
	pub opad: [u32; 8],
	pub hash: [u32; 8],
	pub W: [u32; 8],
	pub rounds: u32,
	pub pass: u32
}

#[repr(align(4))]
#[derive(Clone, Copy)]
pub struct PBKDF2_SHA256_Pass
{
	pub length: u32,
	pub v: [u8; 55]
}

#[repr(align(4))]
#[derive(Clone, Copy)]
pub struct PBKDF2_SHA256_Pass0x1026
{
	pub length: u32,
	pub v: [u8; 1026]
}

#[repr(align(4))]
#[derive(Clone, Copy)]
pub struct PBKDF2_SHA256_Crack
{
	pub digest: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PBKDF2_SHA512_Pass
{
	pub length: u64,
	pub v: [u8; 112],
}

#[repr(align(8))]
#[derive(Clone, Copy)]
pub struct PBKDF2_SHA512_Crack
{
	pub digest: [u8; 64],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PBKDF2_SHA512_Salt
{
	pub length: u32,
	pub rounds: u32,
	pub salt: [u8; 112], //((107 + 1 + 4 + 7) / 8) * 8
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PBKDF2_SHA512_State
{
	pub ipad: [u64; 8],
	pub opad: [u64; 8],
	pub hash: [u64; 8],
	pub W: [u64; 8],
	pub rounds: u32
}