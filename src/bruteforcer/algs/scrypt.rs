#[repr(align(16))]
#[derive(Clone, Copy)]
pub struct TBlock
{
	pub buf: [u32; 256]
}
