#[repr(C)]
#[derive(Clone, Copy)]
pub struct AESGCM_Key
{
	pub key: [u8; 32],
	pub key_len: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AESGCM_IV
{
	pub iv: [u8; 16],
	pub iv_len: u8
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AESGCM_SIV
{
	pub iv: [u8; 12]
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AESGCM_AEAD
{
	pub aead: [u8; 32],
	pub aead_len: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AESGCM_TAG
{
	pub tag: [u8; 16]
}