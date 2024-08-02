use super::*;
use crate::encode_hex;
use super::algs::{ pbkdf2::*, scrypt::* };
use opencl3::program::CL_STD_2_0;
use opencl3::command_queue::CommandQueue;
use opencl3::kernel::ExecuteKernel;
use opencl3::svm::SvmVec;
use opencl3::types::{ cl_uint, cl_int, CL_BLOCKING };
use opencl3::memory::{ CL_MAP_READ, CL_MAP_WRITE };
use std::{ ffi::c_void, sync::Mutex, rc::Rc, cell::RefCell };

pub struct SCryptCase
{
	pub salt: Vec<u8>,
	pub n: u64,
	pub p: u32,
	pub r: u32,
}

pub struct SPBKDF2_HMAC_SHA256_Case
{
	pub salt: Vec<u8>,
	pub iterations: u32,
}

pub enum OPT_PBKDF2_SPHS256_Case
{
	SCrypt(SCryptCase),
	PBKDF2(SPBKDF2_HMAC_SHA256_Case)
}

#[derive(Clone, Copy)]
#[repr(C)]
pub enum OPT_PBKDF2_SPHS256_Cipher
{
	AES_CTR_128,
	AES_CTR_192,
	AES_CTR_256,
}

pub struct OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Request
{
	pub data: Vec<u8>,
	pub iv: Vec<u8>,
	pub mac: Vec<u8>,
	pub predev_salts: Vec<Vec<u8>>,
	pub predev_iterations: u32,
	pub predev_keylen: u32,
	pub keylen: u32,
	pub kdf: OPT_PBKDF2_SPHS256_Case,
	pub cipher: OPT_PBKDF2_SPHS256_Cipher
}

enum OrigPasses
{
	PBKDF2_SHA256(Vec<PBKDF2_SHA256_Pass0x1026>),
	PBKDF2_SHA512(Vec<PBKDF2_SHA512_Pass>),
}

struct GPUBruteForceContext<'a>
{
	queue: &'a CommandQueue,

	//kernels are going here
	pbkdf2_sha256_init_krnl: Rc<WrappedKernel>,
	pbkdf2_sha256_loop_krnl: Rc<WrappedKernel>,
	pbkdf2_sha256_final_krnl: Rc<WrappedKernel>,
	pbkdf2_sha256_init_pi_krnl: Rc<WrappedKernel>,
	pbkdf2_sha256_loop_pi_krnl: Rc<WrappedKernel>,
	pbkdf2_sha256_final_pi_krnl: Rc<WrappedKernel>,
	keccak256_krnl: Rc<WrappedKernel>,
	romix_krnl: Rc<WrappedKernel>,

	//other local stuff goes here
	pbkdf2_sha256_states: Rc<RefCell<SvmVec<'a, PBKDF2_SHA256_State>>>,
	pbkdf2_sha256_passes: Rc<RefCell<SvmVec<'a, PBKDF2_SHA256_Pass0x1026>>>,
	pbkdf2_sha256_cracks: Rc<RefCell<SvmVec<'a, PBKDF2_SHA256_Crack>>>,
	pbkdf2_sha256_config: Rc<RefCell<SvmVec<'a, PBKDF2_SHA256_Config>>>,
	pbkdf2_sha256_salt_svm: Rc<RefCell<SvmVec<'a, u8>>>,
	pbkdf2_sha256_passwords: Vec<PBKDF2_SHA256_Pass0x1026>,
	original_passwords: OrigPasses,

	//romix related
	scrypt_block_X: Rc<Option<RefCell<SvmVec<'a, TBlock>>>>,
	scrypt_block_V: Rc<Option<RefCell<SvmVec<'a, TBlock>>>>,
	
	//keccak related
	keccak256_input: Rc<RefCell<SvmVec<'a, u8>>>,
	keccak256_output: Rc<RefCell<SvmVec<'a, u8>>>,

	//generic
	kdf_case: &'a OPT_PBKDF2_SPHS256_Case,
	cipher: OPT_PBKDF2_SPHS256_Cipher,
	data: &'a Vec<u8>,
	iv: &'a Vec<u8>,
	mac: &'a Vec<u8>,
	keylen: u32,
	keysize: u32,
	size_of_salt: usize,
	scrypt_iters: usize,
	total_keccak256_iters_per_kdf_iter: usize,
	total_keccak256_passes_per_iter: usize
}

trait OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Internal
{
	fn PK2S512SCPK2S256KACC_BruteforceCPUWithPass(data: &Vec<u8>, iv: &Vec<u8>, mac: &[u8; 32], kdf: &OPT_PBKDF2_SPHS256_Case, keylen: u32, cipher: OPT_PBKDF2_SPHS256_Cipher, password: &String) -> Result<Option<(String, String)>, String>;
	fn PK2S512SCPK2S256KACC_BruteforceGPUWithContext<'a>(ctx: GPUBruteForceContext<'a>) -> Result<Option<(String, String)>, String>;
}

#[allow(private_bounds)]
pub trait OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR : OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Internal
{
	fn PK2S512SCPK2S256KACC_BruteforceCPU(req: &OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Request, passwords: &Vec<String>) -> Result<Option<(String, String)>, String>;
	fn PK2S512SCPK2S256KACC_BruteforceGPU(devices: Arc<Vec<GPUDeviceInfo>>, gpupg: Arc<OpenCLProgram>, req: &OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Request, passwords: &Vec<String>) -> Result<Option<(String, String)>, String>;
	fn PK2S512SCPK2S256KACC_LoadKernels(devices: &Arc<Vec<GPUDeviceInfo>>) -> Result<OpenCLProgram, String>;
}

impl OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR for BruteForcer
{
	fn PK2S512SCPK2S256KACC_BruteforceCPU(req: &OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Request, passwords: &Vec<String>) -> Result<Option<(String, String)>, String>
	{
		//algorithm is the following:
		//1. prederive the password using pbkdf2-hmac-sha512 if we have to do that, hexify it after
		//2. run scrypt / pbkdf2-hmac-sha256 on the password and get the derived key
		//3. compute keccak256 mac of the key and encrypted data and compare it against request mac
		//4. if mac matches, then decrypt using specified cipher
		//5. then try to decode it as utf-8 thats it
		let mac: [u8; 32] = req.mac[..].try_into().map_err(|_| "Unexpected MAC len".to_owned())?;
		if req.predev_salts.len() != 0
		{
			//at this point we perform prederivation
			let mut predev = Vec::<u8>::new();
			predev.resize(req.predev_keylen as usize, 0u8);
			for salt in &req.predev_salts
			{
				for password in passwords
				{
					fastpbkdf2::pbkdf2_hmac_sha512(password.as_bytes(), salt, req.predev_iterations, &mut predev);
					let pass = "0x".to_owned() + &encode_hex(&predev);
					match Self::PK2S512SCPK2S256KACC_BruteforceCPUWithPass(&req.data, &req.iv, &mac, &req.kdf, req.keylen, req.cipher, &pass)?
					{
						Some(res) => { return Ok(Some(res)); },
						None => {}
					}
				}
			}
		}
		else
		{
			for password in passwords
			{
				match Self::PK2S512SCPK2S256KACC_BruteforceCPUWithPass(&req.data, &req.iv, &mac, &req.kdf, req.keylen, req.cipher, password)?
				{
					Some(res) => { return Ok(Some(res)); },
					None => {}
				}
			}
		}

		Ok(None)
	}

	fn PK2S512SCPK2S256KACC_BruteforceGPU(devices: Arc<Vec<GPUDeviceInfo>>, gpupg: Arc<OpenCLProgram>, req: &OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Request, passwords: &Vec<String>) -> Result<Option<(String, String)>, String>
	{
		//by specifying 0 we let the device to decide which queue size to use
		//https://registry.khronos.org/OpenCL/sdk/3.0/docs/man/html/clCreateCommandQueueWithProperties.html
		let queue = CommandQueue::create_default_with_properties(&gpupg.ctx, 0, 0).map_err(|e| e.to_string())?;
		let max_mem_per_queue = devices.iter().map(|d| d.max_memory_alloc as usize).collect::<Vec<_>>().into_iter().min().unwrap_or(0);
		if max_mem_per_queue == 0 { return Err("Unexpected max memory value".to_owned()); }

		//first of all we need to determine how many passwords we are capable to bruteforce at once
		//this will be the minimum value of mgws for all our kernels which accept passwords
		let pbkdf2_sha256_init_krnl = Rc::new(WrappedKernel::clone(gpupg.krnls.get("pbkdf2_sha256_init").unwrap()));
		let pbkdf2_sha256_loop_krnl = Rc::new(WrappedKernel::clone(gpupg.krnls.get("pbkdf2_sha256_loop").unwrap()));
		let pbkdf2_sha256_final_krnl = Rc::new(WrappedKernel::clone(gpupg.krnls.get("pbkdf2_sha256_final").unwrap()));
		let pbkdf2_sha256_init_pi_krnl = Rc::new(WrappedKernel::clone(gpupg.krnls.get("pbkdf2_sha256_init_pi").unwrap()));
		let pbkdf2_sha256_loop_pi_krnl = Rc::new(WrappedKernel::clone(gpupg.krnls.get("pbkdf2_sha256_loop_pi").unwrap()));
		let pbkdf2_sha256_final_pi_krnl = Rc::new(WrappedKernel::clone(gpupg.krnls.get("pbkdf2_sha256_final_pi").unwrap()));
		let keccak256_krnl = Rc::new(WrappedKernel::clone(gpupg.krnls.get("keccak256").unwrap()));
		let romix_krnl = Rc::new(WrappedKernel::clone(gpupg.krnls.get("ROMix").unwrap()));

		//find out how many pbkdf passes per iter we actually can handle, the values for per instance variants must be the same actually...
		let mut max_global_work_size = vec![
				pbkdf2_sha256_init_krnl.mgws,
				pbkdf2_sha256_loop_krnl.mgws,
				pbkdf2_sha256_final_krnl.mgws,
				keccak256_krnl.mgws,
				romix_krnl.mgws,
				passwords.len()]
			.into_iter().min().unwrap_or(0);

		if max_global_work_size == 0 { return Err("Unexpected global work size".to_owned()); }

		let data_len_with_key = req.data.len() + req.keylen as usize;
		let max_arg_size = devices.iter().map(|d| d.max_single_argument_size as usize).collect::<Vec<_>>().into_iter().min().unwrap_or(0);
		if max_arg_size < std::mem::size_of::<PBKDF2_SHA256_State>() ||
			max_arg_size < std::mem::size_of::<PBKDF2_SHA256_Pass0x1026>() ||
			max_arg_size < std::mem::size_of::<PBKDF2_SHA256_Crack>() ||
			max_arg_size < std::mem::size_of::<PBKDF2_SHA256_Salt>() ||
			max_arg_size < std::mem::size_of::<PBKDF2_SHA256_Config>() ||
			max_arg_size < std::mem::size_of::<TBlock>() ||
			max_arg_size < data_len_with_key
		{
			return Err("Too little memory for an argument".to_owned());
		}

		if req.predev_keylen > 512
		{ return Err("Cannot derive more than 512 bytes at the moment".to_owned()); }

		let keysize = match req.cipher
		{
			OPT_PBKDF2_SPHS256_Cipher::AES_CTR_128 => 16u32,
			OPT_PBKDF2_SPHS256_Cipher::AES_CTR_192 => 24u32,
			OPT_PBKDF2_SPHS256_Cipher::AES_CTR_256 => 32u32,
		};

		if keysize > req.keylen
		{ return Err("Invalid key length".to_owned()); }

		//take valid passwords here
		let mut pwds = passwords.iter().filter_map(|p| if p.len() <= 55
		{
			let plen = p.len();
			let mut r = PBKDF2_SHA256_Pass0x1026
			{
				length: plen as u32,
				v: unsafe { std::mem::MaybeUninit::uninit().assume_init() }
			};
			r.v[..plen].copy_from_slice(p.as_bytes());
			Some(r)
		} else { None }).collect::<Vec<_>>();

		if pwds.len() == 0
		{ return Err("No valid passwords to use in bruteforce".to_owned()); }

		//and now compute actual values, how many we can allocate per request? This will be our actual limit
		let total_pbkdf2_sha256_request_size_no_salt = std::mem::size_of::<PBKDF2_SHA256_State>() +
			std::mem::size_of::<PBKDF2_SHA256_Pass0x1026>() +
			std::mem::size_of::<PBKDF2_SHA256_Crack>();
		
		let size_of_salt;
		let mut total_passes_per_iter;
		let mut total_iters_with_salt;
		let mut scrypt_iters = 0usize;
		let mut scrypt_alloc_blocks_V = 0usize;
		let pbkdf2_salt_svm;

		match &req.kdf
		{
			OPT_PBKDF2_SPHS256_Case::SCrypt(case) =>
			{
				//in case if we gonna bruteforce scrypt we need to figure out how many romix iters we can handle per request
				size_of_salt = (case.p * case.r * 128u32) as usize + std::mem::size_of::<cl_uint>();
				let size_of_V = (case.n * (case.r as u64) * 128u64) as usize;
				if max_mem_per_queue < size_of_salt || max_mem_per_queue < size_of_V
				{ return Err("Too little memory for an argument".to_owned()); }

				//in this case the salt is individual
				let total_pbkdf2_sha256_request_size = total_pbkdf2_sha256_request_size_no_salt + size_of_salt;
				let total_pbkdf2_sha256_mem = pwds.len() * total_pbkdf2_sha256_request_size;
				let total_pbkdf2_sha256_iters = (total_pbkdf2_sha256_mem + max_mem_per_queue - 1) / max_mem_per_queue;
				
				//scrypt related
				let max_single_argument_size = std::cmp::max(size_of_V, std::mem::size_of::<TBlock>());
				let blocks_per_iter_needed = max_single_argument_size / std::mem::size_of::<TBlock>();
				scrypt_iters = std::cmp::min((max_mem_per_queue + blocks_per_iter_needed - 1) / blocks_per_iter_needed, total_pbkdf2_sha256_iters);

				//how many blocks we need per request?
				scrypt_alloc_blocks_V = (size_of_V * scrypt_iters) / std::mem::size_of::<TBlock>();
				total_iters_with_salt = total_pbkdf2_sha256_iters;
				total_passes_per_iter = std::cmp::min(max_mem_per_queue / total_pbkdf2_sha256_request_size_no_salt, max_global_work_size);
				pbkdf2_salt_svm = Rc::new(RefCell::new(SvmVec::<u8>::allocate(&gpupg.ctx, size_of_salt * total_passes_per_iter).map_err(|e| e.to_string())?)); //in this case the salt is individal
			},
			OPT_PBKDF2_SPHS256_Case::PBKDF2(case) =>
			{
				size_of_salt = case.salt.len() + std::mem::size_of::<cl_uint>();
				let total_pbkdf2_sha256_mem_no_salt = pwds.len() * total_pbkdf2_sha256_request_size_no_salt;
				let total_pbkdf2_sha256_iters_no_salt = (total_pbkdf2_sha256_mem_no_salt + max_mem_per_queue - 1) / max_mem_per_queue;
				let total_pbkdf2_sha256_iters_with_salt = (total_pbkdf2_sha256_mem_no_salt + (total_pbkdf2_sha256_iters_no_salt * size_of_salt) + max_mem_per_queue - 1) / max_mem_per_queue;
				debug_assert!(total_pbkdf2_sha256_iters_with_salt >= total_pbkdf2_sha256_iters_no_salt);
				total_iters_with_salt = total_pbkdf2_sha256_iters_with_salt;
				total_passes_per_iter = std::cmp::min((max_mem_per_queue - std::cmp::min(max_mem_per_queue, size_of_salt)) / total_pbkdf2_sha256_request_size_no_salt, max_global_work_size);
				pbkdf2_salt_svm = Rc::new(RefCell::new(SvmVec::<u8>::allocate(&gpupg.ctx, size_of_salt).map_err(|e| e.to_string())?)); //in this case salt is static
			} 
		}

		if total_passes_per_iter == 0 { return Err("Unexpected passes per iteration amount (pbkdf2)".to_owned()); }

		//how many keccak256 iters per kdf iter we can do?
		let total_keccak256_pass_size = std::mem::size_of::<cl_uint>() + data_len_with_key;
		let total_keccak256_passes_per_iter = max_mem_per_queue / total_keccak256_pass_size;
		let total_keccak256_passes_clamped = vec![total_keccak256_passes_per_iter, total_passes_per_iter, keccak256_krnl.mgws].into_iter().min().unwrap_or(0);
		if total_keccak256_passes_clamped == 0 { return Err("Unexpected passes per iteration amount (keccak256)".to_owned()); }
		let mut total_keccak256_iters_per_kdf_iter = (total_keccak256_passes_clamped + total_passes_per_iter - 1) / total_passes_per_iter;

		//figure out if we have to use pbkdf_hmac_sha512 kernel, it is only used if we need to hash the password (so it is optional)
		//if there no salts, then we don't need to hash the password and we gonna use it "as is"
		if req.predev_salts.len() != 0
		{
			//in this case we only support passwords with maximum size of 110 (should be enough actually, for now)
			let mut pwds = pwds.into_iter().filter_map(|v| if v.length <= 110
			{
				let len = v.length as usize;
				let mut pass = PBKDF2_SHA512_Pass
				{
					length: len as u64,
					v: [0u8; 112]
				};
				pass.v[..len].copy_from_slice(&v.v[..len]);
				Some(pass)
			} else { None }).collect::<Vec<_>>();
			if pwds.len() == 0
			{ return Err("No valid passwords to use in bruteforce".to_owned()); }

			let mut salts = req.predev_salts.iter().filter_map(|s| if s.len() <= 107
			{
				let len = s.len();
				let lenwctr = len + 5;
				let mut r = PBKDF2_SHA512_Salt
				{
					length: lenwctr as u32,
					salt: [0u8; 112],
					rounds: req.predev_iterations
				};
				r.salt[..len].copy_from_slice(s);
				r.salt[len + 4] = 0x80;
				Some(r)
			} else { None }).collect::<Vec<_>>();
			if salts.len() == 0
			{ return Err("No valid salts to use in bruteforce".to_owned()); }

			//modify max global work size
			let pbkdf2_sha512_kernel_krnl = WrappedKernel::clone(gpupg.krnls.get("pbkdf2_sha512_kernel").unwrap());
			let pbkdf2_sha512_loop_krnl = WrappedKernel::clone(gpupg.krnls.get("pbkdf2_sha512_loop").unwrap());
			max_global_work_size = vec![max_global_work_size, pbkdf2_sha512_kernel_krnl.mgws, pbkdf2_sha512_loop_krnl.mgws, pwds.len()].into_iter().min().unwrap_or(0);
			if max_global_work_size == 0 { return Err("Unexpected global work size (pbkdf2 sha512)".to_owned()); }

			//figure out how many actual pbkdf2-hmac-sha512 iters we can do
			let size_of_salt = std::mem::size_of::<PBKDF2_SHA512_Salt>();
			let total_pbkdf2_sha512_request_size_no_salt = std::mem::size_of::<PBKDF2_SHA512_State>() +
				std::mem::size_of::<PBKDF2_SHA512_Pass>() +
				std::mem::size_of::<PBKDF2_SHA512_Crack>();

			let total_pbkdf2_sha512_mem_no_salt = pwds.len() * total_pbkdf2_sha512_request_size_no_salt;
			let total_pbkdf2_sha512_iters_no_salt = (total_pbkdf2_sha512_mem_no_salt + max_mem_per_queue - 1) / max_mem_per_queue;
			let total_pbkdf2_sha512_iters_with_salt = (total_pbkdf2_sha512_mem_no_salt + (total_pbkdf2_sha512_iters_no_salt * size_of_salt) + max_mem_per_queue - 1) / max_mem_per_queue;
			debug_assert!(total_pbkdf2_sha512_iters_with_salt >= total_pbkdf2_sha512_iters_no_salt);

			//figure out amount of passes per iteration and recalc original values
			let total_pbkdf2_sha512_passes_per_iter = std::cmp::min((max_mem_per_queue - std::cmp::min(max_mem_per_queue, size_of_salt)) / total_pbkdf2_sha512_request_size_no_salt, max_global_work_size);
			total_passes_per_iter = std::cmp::min(total_passes_per_iter, total_pbkdf2_sha512_passes_per_iter);
			total_iters_with_salt = (pwds.len() + total_passes_per_iter - 1) / total_passes_per_iter;
			total_keccak256_iters_per_kdf_iter = (total_keccak256_passes_clamped + total_passes_per_iter - 1) / total_passes_per_iter;

			//now preallocate some buffers which we gonna use later
			let key_size_kck = (req.keylen - (req.keylen - keysize)) as usize;
			let data_len_with_key_stripped = req.data.len() + key_size_kck as usize;
			let pbkdf2_sha256_states = Rc::new(RefCell::new(SvmVec::<PBKDF2_SHA256_State>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?));
			let pbkdf2_sha256_passes = Rc::new(RefCell::new(SvmVec::<PBKDF2_SHA256_Pass0x1026>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?));
			let pbkdf2_sha256_cracks = Rc::new(RefCell::new(SvmVec::<PBKDF2_SHA256_Crack>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?));
			let pbkdf2_sha256_config = Rc::new(RefCell::new(SvmVec::<PBKDF2_SHA256_Config>::allocate(&gpupg.ctx, 1).map_err(|e| e.to_string())?));
			let scrypt_block_X = Rc::new(if scrypt_iters != 0 { Some(RefCell::new(SvmVec::<TBlock>::allocate(&gpupg.ctx, scrypt_iters).map_err(|e| e.to_string())?)) } else { None });
			let scrypt_block_V = Rc::new(if scrypt_alloc_blocks_V != 0 { Some(RefCell::new(SvmVec::<TBlock>::allocate(&gpupg.ctx, scrypt_alloc_blocks_V).map_err(|e| e.to_string())?)) } else { None });
			let keccak256_input = Rc::new(RefCell::new(SvmVec::<u8>::allocate(&gpupg.ctx, total_passes_per_iter * data_len_with_key_stripped).map_err(|e| e.to_string())?));
			let keccak256_output = Rc::new(RefCell::new(SvmVec::<u8>::allocate(&gpupg.ctx, 32 * total_passes_per_iter).map_err(|e| e.to_string())?));
			
			//and also preallocate buffers we gonna use to prederive the key
			let mut pbkdf2_sha512_states = SvmVec::<PBKDF2_SHA512_State>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?;
			let mut pbkdf2_sha512_passes = SvmVec::<PBKDF2_SHA512_Pass>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?;
			let mut pbkdf2_sha512_cracks = SvmVec::<PBKDF2_SHA512_Crack>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?;
			let mut pbkdf2_sha512_salt = SvmVec::<PBKDF2_SHA512_Salt>::allocate(&gpupg.ctx, 1).map_err(|e| e.to_string())?;
		
			//figure out how many pbkdf2-sha512 passes we need to perform
			let predev_key_passes = ((req.predev_keylen + 63) / 64) + 1;
			let pbkdf2_sha512_loops = (req.predev_iterations + HASH_LOOPS_SHA512 - 1) / HASH_LOOPS_SHA512;
			let mut prederived_keys = Vec::<Vec<u8>>::new();
			prederived_keys.resize_with(total_passes_per_iter, || { let mut v = Vec::<u8>::with_capacity(req.predev_keylen as usize); v.resize(req.predev_keylen as usize, 0u8); v } );

			//prepare keccak256 input data
			unsafe
			{
				let input = &mut *keccak256_input.borrow_mut();
				if !input.is_fine_grained() { queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, input, &[]).map_err(|e| e.to_string())?; }
				for i in 0..total_passes_per_iter
				{
					let ptr = input.as_mut_ptr().offset(((data_len_with_key_stripped * i) + key_size_kck as usize) as isize);
					std::ptr::copy_nonoverlapping(req.data.as_ptr(), ptr, req.data.len());
				}
				if !input.is_fine_grained() { queue.enqueue_svm_unmap(input, &[]).map_err(|e| e.to_string())?; }
			}

			//now actually prederive
			for salt in &mut salts
			{
				for _ in 0..total_iters_with_salt
				{
					//fill our passwords buffer now, this is the only buffer we need to fill now
					let passes_this_time = std::cmp::min(pwds.len(), total_passes_per_iter);
					let remaining = pwds.split_off(passes_this_time);
					let to_pass = std::mem::replace(&mut pwds, remaining);
					unsafe
					{
						if !pbkdf2_sha512_passes.is_fine_grained() { queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, &mut pbkdf2_sha512_passes, &[]).map_err(|e| e.to_string())?; }
						std::ptr::copy_nonoverlapping(to_pass.as_ptr(), pbkdf2_sha512_passes.as_mut_ptr(), passes_this_time);
						if !pbkdf2_sha512_passes.is_fine_grained() { queue.enqueue_svm_unmap(&pbkdf2_sha512_passes, &[]).map_err(|e| e.to_string())?; }
					}

					for predev_pass in 1..predev_key_passes
					{
						//take the salt we gonna use this time for derivation
						unsafe
						{
							//this includes 0x80 too, we don't want to modify it
							let salt_len_wctr = salt.length as usize - 1;
							let salt_len = salt_len_wctr - 4;
							salt.salt[salt_len..salt_len_wctr].copy_from_slice(&predev_pass.to_be_bytes());
							if !pbkdf2_sha512_salt.is_fine_grained() { queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, &mut pbkdf2_sha512_salt, &[]).map_err(|e| e.to_string())?; }
							pbkdf2_sha512_salt.copy_from_slice(&[salt.clone()]);
							if !pbkdf2_sha512_salt.is_fine_grained() { queue.enqueue_svm_unmap(&pbkdf2_sha512_salt, &[]).map_err(|e| e.to_string())?; }
						}

						//TODO: Optimize by splitting the kernel like it was done for pbkdf2-sha256
						let event = unsafe
						{
							let mut kernel = ExecuteKernel::new(&pbkdf2_sha512_kernel_krnl.krnl);
							kernel.set_arg_svm(pbkdf2_sha512_passes.as_ptr())
								.set_arg_svm(pbkdf2_sha512_salt.as_ptr())
								.set_arg_svm(pbkdf2_sha512_states.as_mut_ptr());
							let event = kernel.set_global_work_size(passes_this_time)
								.enqueue_nd_range(&queue).map_err(|e| e.to_string())?;
							event
						};

						event.wait().map_err(|e| e.to_string())?;

						{
							let mut kernel = ExecuteKernel::new(&pbkdf2_sha512_loop_krnl.krnl);
							for _ in 0..pbkdf2_sha512_loops
							{
								let event = unsafe
								{
									kernel.set_arg_svm(pbkdf2_sha512_states.as_mut_ptr())
										.set_arg_svm(pbkdf2_sha512_cracks.as_mut_ptr())
										.set_global_work_size(passes_this_time)
										.enqueue_nd_range(&queue).map_err(|e| e.to_string())?
								};
								queue.finish().map_err(|e| e.to_string())?;
								event.wait().map_err(|e| e.to_string())?;
							}
						}

						//copy the prederived bytes now
						let copy_offset = ((predev_pass - 1) * 64) as usize;
						let to_copy = std::cmp::min(std::cmp::max(req.predev_keylen as usize, copy_offset) - copy_offset, 64);
						if !pbkdf2_sha512_cracks.is_fine_grained() { unsafe { queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_READ, &mut pbkdf2_sha512_cracks, &[])? }; }
						let cracks_local = pbkdf2_sha512_cracks[..passes_this_time].to_vec();
						if !pbkdf2_sha512_cracks.is_fine_grained() { unsafe { queue.enqueue_svm_unmap(&pbkdf2_sha512_cracks, &[]).map_err(|e| e.to_string())? }; }

						for i in 0..passes_this_time
						{
							let cracked = &cracks_local[i];
							let key = &mut prederived_keys[i];
							unsafe { std::ptr::copy_nonoverlapping(cracked.digest.as_ptr(), key[copy_offset..(copy_offset + to_copy)].as_mut_ptr(), to_copy); }
						}
					}

					//now we need to format the key results to use it in kdf as passwords
					let mut passwords = Vec::<PBKDF2_SHA256_Pass0x1026>::with_capacity(passes_this_time);
					for i in 0..passes_this_time
					{
						let key = &prederived_keys[i];
						let encoded_as_hex = "0x".to_owned() + &encode_hex(key);
						let pass = PBKDF2_SHA256_Pass0x1026
						{
							length: 1026,
							v: encoded_as_hex.into_bytes().try_into().unwrap(),
						};
						passwords.push(pass);
					}

					//and so now perform the actual bruteforce
					let bf_ctx = GPUBruteForceContext
					{
						queue: &queue,
						pbkdf2_sha256_init_krnl: Rc::clone(&pbkdf2_sha256_init_krnl), pbkdf2_sha256_loop_krnl: Rc::clone(&pbkdf2_sha256_loop_krnl),
						pbkdf2_sha256_final_krnl: Rc::clone(&pbkdf2_sha256_final_krnl), pbkdf2_sha256_init_pi_krnl: Rc::clone(&pbkdf2_sha256_init_pi_krnl),
						pbkdf2_sha256_loop_pi_krnl: Rc::clone(&pbkdf2_sha256_loop_pi_krnl), pbkdf2_sha256_final_pi_krnl: Rc::clone(&pbkdf2_sha256_final_pi_krnl),
						keccak256_krnl: Rc::clone(&keccak256_krnl), romix_krnl: Rc::clone(&romix_krnl),
						pbkdf2_sha256_states: Rc::clone(&pbkdf2_sha256_states), pbkdf2_sha256_passes: Rc::clone(&pbkdf2_sha256_passes), pbkdf2_sha256_cracks: Rc::clone(&pbkdf2_sha256_cracks),
						pbkdf2_sha256_config: Rc::clone(&pbkdf2_sha256_config), pbkdf2_sha256_salt_svm: Rc::clone(&pbkdf2_salt_svm),
						pbkdf2_sha256_passwords: passwords, original_passwords: OrigPasses::PBKDF2_SHA512(to_pass), scrypt_block_X: Rc::clone(&scrypt_block_X), scrypt_block_V: Rc::clone(&scrypt_block_V),
						keccak256_input: Rc::clone(&keccak256_input), keccak256_output: Rc::clone(&keccak256_output),
						kdf_case: &req.kdf, cipher: req.cipher, data: &req.data, iv: &req.iv, mac: &req.mac, keylen: req.keylen, keysize,
						size_of_salt, scrypt_iters, total_keccak256_iters_per_kdf_iter, total_keccak256_passes_per_iter: total_keccak256_passes_clamped
					};

					let result = Self::PK2S512SCPK2S256KACC_BruteforceGPUWithContext(bf_ctx);
					match result
					{
						Err(e) => { return Err(e); },
						Ok(res) => { if res.is_some() { return Ok(res); } }
					}
				}
			}
		}
		else
		{
			//we allocate them here because of true case where we also get some conditions
			//we first check these conds and then allocate vecs to avoid extra allocation in case if we exit
			//so yeah this one is ugly, however it is needed for optimizations too
			let key_size_kck = (req.keylen - (req.keylen - keysize)) as usize;
			let data_len_with_key_stripped = req.data.len() + key_size_kck as usize;
			let pbkdf2_states = Rc::new(RefCell::new(SvmVec::<PBKDF2_SHA256_State>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?));
			let pbkdf2_passes = Rc::new(RefCell::new(SvmVec::<PBKDF2_SHA256_Pass0x1026>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?));
			let pbkdf2_cracks = Rc::new(RefCell::new(SvmVec::<PBKDF2_SHA256_Crack>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?));
			let pbkdf2_config = Rc::new(RefCell::new(SvmVec::<PBKDF2_SHA256_Config>::allocate(&gpupg.ctx, 1).map_err(|e| e.to_string())?));
			let scrypt_block_X = Rc::new(if scrypt_iters != 0 { Some(RefCell::new(SvmVec::<TBlock>::allocate(&gpupg.ctx, scrypt_iters).map_err(|e| e.to_string())?)) } else { None });
			let scrypt_block_V = Rc::new(if scrypt_alloc_blocks_V != 0 { Some(RefCell::new(SvmVec::<TBlock>::allocate(&gpupg.ctx, scrypt_alloc_blocks_V).map_err(|e| e.to_string())?)) } else { None });
			let keccak256_input = Rc::new(RefCell::new(SvmVec::<u8>::allocate(&gpupg.ctx, total_passes_per_iter * data_len_with_key_stripped).map_err(|e| e.to_string())?));
			let keccak256_output = Rc::new(RefCell::new(SvmVec::<u8>::allocate(&gpupg.ctx, 32 * total_passes_per_iter).map_err(|e| e.to_string())?));

			//prepare keccak256 input data
			unsafe
			{
				let input = &mut *keccak256_input.borrow_mut();
				if !input.is_fine_grained() { queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, input, &[]).map_err(|e| e.to_string())?; }
				for i in 0..total_passes_per_iter
				{
					let ptr = input.as_mut_ptr().offset(((data_len_with_key_stripped * i) + key_size_kck as usize) as isize);
					std::ptr::copy_nonoverlapping(req.data.as_ptr(), ptr, req.data.len());
				}
				if !input.is_fine_grained() { queue.enqueue_svm_unmap(input, &[]).map_err(|e| e.to_string())?; }
			}

			for _ in 0..total_iters_with_salt
			{
				//fill our passwords buffer now, this is the only buffer we need to fill now
				let passes_this_time = std::cmp::min(pwds.len(), total_passes_per_iter);
				let remaining = pwds.split_off(passes_this_time);
				let to_pass = std::mem::replace(&mut pwds, remaining);

				//and so now perform the actual bruteforce
				let bf_ctx = GPUBruteForceContext
				{
					queue: &queue,
					pbkdf2_sha256_init_krnl: Rc::clone(&pbkdf2_sha256_init_krnl), pbkdf2_sha256_loop_krnl: Rc::clone(&pbkdf2_sha256_loop_krnl),
					pbkdf2_sha256_final_krnl: Rc::clone(&pbkdf2_sha256_final_krnl), pbkdf2_sha256_init_pi_krnl: Rc::clone(&pbkdf2_sha256_init_pi_krnl),
					pbkdf2_sha256_loop_pi_krnl: Rc::clone(&pbkdf2_sha256_loop_pi_krnl), pbkdf2_sha256_final_pi_krnl: Rc::clone(&pbkdf2_sha256_final_pi_krnl),
					keccak256_krnl: Rc::clone(&keccak256_krnl), romix_krnl: Rc::clone(&romix_krnl),
					pbkdf2_sha256_states: Rc::clone(&pbkdf2_states), pbkdf2_sha256_passes: Rc::clone(&pbkdf2_passes), pbkdf2_sha256_cracks: Rc::clone(&pbkdf2_cracks),
					pbkdf2_sha256_config: Rc::clone(&pbkdf2_config), pbkdf2_sha256_salt_svm: Rc::clone(&pbkdf2_salt_svm),
					pbkdf2_sha256_passwords: to_pass.clone(), original_passwords: OrigPasses::PBKDF2_SHA256(to_pass), scrypt_block_X: Rc::clone(&scrypt_block_X), scrypt_block_V: Rc::clone(&scrypt_block_V),
					keccak256_input: Rc::clone(&keccak256_input), keccak256_output: Rc::clone(&keccak256_output),
					kdf_case: &req.kdf, cipher: req.cipher, data: &req.data, iv: &req.iv, mac: &req.mac, keylen: req.keylen, keysize,
					size_of_salt, scrypt_iters, total_keccak256_iters_per_kdf_iter, total_keccak256_passes_per_iter: total_keccak256_passes_clamped
				};

				let result = Self::PK2S512SCPK2S256KACC_BruteforceGPUWithContext(bf_ctx);
				match result
				{
					Err(e) => { return Err(e); },
					Ok(res) => { if res.is_some() { return Ok(res); } }
				}
			}
		}

		Ok(None)
	}

	fn PK2S512SCPK2S256KACC_LoadKernels(devices: &Arc<Vec<GPUDeviceInfo>>) -> Result<OpenCLProgram, String>
	{
		let devices_p = devices.iter().map(|d| d.device.id()).collect::<Vec<_>>();
		let context = Context::from_devices(&devices_p, &[], None, std::ptr::null_mut::<c_void>()).map_err(|e| e.to_string())?;

		let pbkdf2_hmac_sha256_single = String::from_utf8(include_bytes!("./cl/pbkdf2_hmac_sha256_single.cl").to_vec()).map_err(|e| e.to_string())?;
		let pbkdf2_hmac_sha512_single = String::from_utf8(include_bytes!("./cl/pbkdf2_hmac_sha512_single.cl").to_vec()).map_err(|e| e.to_string())?;
		let scrypt_single = String::from_utf8(include_bytes!("./cl/scrypt_single.cl").to_vec()).map_err(|e| e.to_string())?;
		let keccak256_single = String::from_utf8(include_bytes!("./cl/keccak256_single.cl").to_vec()).map_err(|e| e.to_string())?;

		let program1 = Program::create_and_build_from_source(&context, &pbkdf2_hmac_sha256_single, &vec![CL_STD_2_0, "-DPLAINTEXT_LENGTH=1026 -DSALT_GLOBAL_CONST=1 -DCFG_GLOBAL_CONST=1 "].concat()).map_err(|e| e.to_string())?;
		let pbkdf2_sha256_init_krnl = Kernel::create(&program1, "pbkdf2_sha256_init").map_err(|e| e.to_string())?;
		let pbkdf2_sha256_loop_krnl = Kernel::create(&program1, "pbkdf2_sha256_loop").map_err(|e| e.to_string())?;
		let pbkdf2_sha256_final_krnl = Kernel::create(&program1, "pbkdf2_sha256_final").map_err(|e| e.to_string())?;

		let program2 = Program::create_and_build_from_source(&context, &pbkdf2_hmac_sha256_single, &vec![CL_STD_2_0, "-DPLAINTEXT_LENGTH=1026 -DSALT_GLOBAL_CONST=1 -DCFG_GLOBAL_CONST=1 -DSALT_PER_IDX=1 "].concat()).map_err(|e| e.to_string())?;
		let pbkdf2_sha256_init_pi_krnl = Kernel::create(&program2, "pbkdf2_sha256_init").map_err(|e| e.to_string())?;
		let pbkdf2_sha256_loop_pi_krnl = Kernel::create(&program2, "pbkdf2_sha256_loop").map_err(|e| e.to_string())?;
		let pbkdf2_sha256_final_pi_krnl = Kernel::create(&program2, "pbkdf2_sha256_final").map_err(|e| e.to_string())?;

		let program3 = Program::create_and_build_from_source(&context, &pbkdf2_hmac_sha512_single, CL_STD_2_0).map_err(|e| e.to_string())?;
		let pbkdf2_sha512_kernel_krnl = Kernel::create(&program3, "pbkdf2_sha512_kernel").map_err(|e| e.to_string())?;
		let pbkdf2_sha512_loop_krnl = Kernel::create(&program3, "pbkdf2_sha512_loop").map_err(|e| e.to_string())?;

		let program4 = Program::create_and_build_from_source(&context, &scrypt_single, CL_STD_2_0).map_err(|e| e.to_string())?;
		let romix_krnl = Kernel::create(&program4, "ROMix").map_err(|e| e.to_string())?;

		let program5 = Program::create_and_build_from_source(&context, &keccak256_single, CL_STD_2_0).map_err(|e| e.to_string())?;
		let keccak256_krnl = Kernel::create(&program5, "keccak256").map_err(|e| e.to_string())?;
		let program = vec![program1, program2, program3, program4, program5];

		let pbkdf2_sha256_init_mgws = devices.iter().map(|d| pbkdf2_sha256_init_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let pbkdf2_sha256_loop_mgws = devices.iter().map(|d| pbkdf2_sha256_loop_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let pbkdf2_sha256_final_mgws = devices.iter().map(|d| pbkdf2_sha256_final_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let pbkdf2_sha256_init_pi_mgws = devices.iter().map(|d| pbkdf2_sha256_init_pi_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let pbkdf2_sha256_loop_pi_mgws = devices.iter().map(|d| pbkdf2_sha256_loop_pi_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let pbkdf2_sha256_final_pi_mgws = devices.iter().map(|d| pbkdf2_sha256_final_pi_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let pbkdf2_sha512_kernel_mgws = devices.iter().map(|d| pbkdf2_sha512_kernel_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let pbkdf2_sha512_loop_mgws = devices.iter().map(|d| pbkdf2_sha512_loop_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let romix_mgws = devices.iter().map(|d| romix_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let keccak256_mgws = devices.iter().map(|d| keccak256_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);

		let mut kernels = HashMap::new();
		kernels.insert("pbkdf2_sha256_init", WrappedKernel{ krnl: pbkdf2_sha256_init_krnl, mgws: pbkdf2_sha256_init_mgws, mtx: Mutex::new(()) });
		kernels.insert("pbkdf2_sha256_loop", WrappedKernel{ krnl: pbkdf2_sha256_loop_krnl, mgws: pbkdf2_sha256_loop_mgws, mtx: Mutex::new(()) });
		kernels.insert("pbkdf2_sha256_final", WrappedKernel{ krnl: pbkdf2_sha256_final_krnl, mgws: pbkdf2_sha256_final_mgws, mtx: Mutex::new(()) });
		kernels.insert("pbkdf2_sha256_init_pi", WrappedKernel{ krnl: pbkdf2_sha256_init_pi_krnl, mgws: pbkdf2_sha256_init_pi_mgws, mtx: Mutex::new(()) });
		kernels.insert("pbkdf2_sha256_loop_pi", WrappedKernel{ krnl: pbkdf2_sha256_loop_pi_krnl, mgws: pbkdf2_sha256_loop_pi_mgws, mtx: Mutex::new(()) });
		kernels.insert("pbkdf2_sha256_final_pi", WrappedKernel{ krnl: pbkdf2_sha256_final_pi_krnl, mgws: pbkdf2_sha256_final_pi_mgws, mtx: Mutex::new(()) });
		kernels.insert("pbkdf2_sha512_kernel", WrappedKernel{ krnl: pbkdf2_sha512_kernel_krnl, mgws: pbkdf2_sha512_kernel_mgws, mtx: Mutex::new(()) });
		kernels.insert("pbkdf2_sha512_loop", WrappedKernel{ krnl: pbkdf2_sha512_loop_krnl, mgws: pbkdf2_sha512_loop_mgws, mtx: Mutex::new(()) });
		kernels.insert("ROMix", WrappedKernel{ krnl: romix_krnl, mgws: romix_mgws, mtx: Mutex::new(()) });
		kernels.insert("keccak256", WrappedKernel{ krnl: keccak256_krnl, mgws: keccak256_mgws, mtx: Mutex::new(()) });

		Ok(OpenCLProgram
		{
			ctx: context,
			pgs: program,
			krnls: kernels
		})
	}
}

impl OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Internal for BruteForcer
{
	fn PK2S512SCPK2S256KACC_BruteforceGPUWithContext<'a>(ctx: GPUBruteForceContext<'a>) -> Result<Option<(String, String)>, String>
	{
		//prepare some
		let keylen = ctx.keylen as usize;
		let passwords = ctx.pbkdf2_sha256_passwords;
		let mut key_results = Vec::<Vec<u8>>::with_capacity(passwords.len());
		key_results.resize_with(passwords.len(), || { let mut v = Vec::<u8>::new(); v.resize(keylen, 0u8); v });
		let keccak256_krnl = ctx.keccak256_krnl;
		let passes_this_time = passwords.len();

		let mut derived_keys = Vec::<Vec<u8>>::new();

		match ctx.kdf_case
		{
			OPT_PBKDF2_SPHS256_Case::SCrypt(case) =>
			{
				if ctx.scrypt_iters == 0
				{ return Err("Scrypt: Got zero possible iterations".to_owned()); }

				let Some(scrypt_block_X_rc) = ctx.scrypt_block_X.as_ref() else { return Err("Scrypt: No X block argument set".to_owned()); };
				let Some(scrypt_block_V_rc) = ctx.scrypt_block_V.as_ref() else { return Err("Scrypt: No V block argument set".to_owned()); };

				let scrypt_block_X = &mut *scrypt_block_X_rc.borrow_mut();
				let scrypt_block_V = &mut *scrypt_block_V_rc.borrow_mut();
				
				//in this case we first perform pbkdf2 with the provided salt as in the single pbkdf2 case
				//then we get the derived keys which will be huge in this case and pass them to romix function
				//then we we use the result as out new salts for pbkdf2 functions where the salt will be per instance
				//the resulting data are our derived keys thats it
				let pbkdf2_sha256_init_krnl = ctx.pbkdf2_sha256_init_krnl;
				let pbkdf2_sha256_loop_krnl = ctx.pbkdf2_sha256_loop_krnl;
				let pbkdf2_sha256_final_krnl = ctx.pbkdf2_sha256_final_krnl;
				let pbkdf2_sha256_init_pi_krnl = ctx.pbkdf2_sha256_init_pi_krnl;
				let pbkdf2_sha256_loop_pi_krnl = ctx.pbkdf2_sha256_loop_pi_krnl;
				let pbkdf2_sha256_final_pi_krnl = ctx.pbkdf2_sha256_final_pi_krnl;
				let romix_krnl = ctx.romix_krnl;
				
				//actually huge
				let scrypt_block_size = case.r * 128;
				let scrypt_key_len = case.p * scrypt_block_size;
				let mut total_derivations = (scrypt_key_len + 31) / 32;
				derived_keys.resize_with(passwords.len(), || { let mut v = Vec::<u8>::with_capacity(scrypt_key_len as usize); v.resize(scrypt_key_len as usize, 0u8); v } );

				let passes = &mut *ctx.pbkdf2_sha256_passes.borrow_mut();
				let salt = &mut *ctx.pbkdf2_sha256_salt_svm.borrow_mut();

				//we copy paste the stuff from pbkdf2 case, we don't need to follow DRY here for optimization
				unsafe
				{
					if !passes.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, passes, &[])?; }
					std::ptr::copy_nonoverlapping(passwords.as_ptr(), passes.as_mut_ptr(), passes_this_time);
					if !passes.is_fine_grained() { ctx.queue.enqueue_svm_unmap(passes, &[]).map_err(|e| e.to_string())?; }

					let salt_len = case.salt.len();
					let mut salt_buffer = Vec::<u8>::new();
					salt_buffer.resize(std::mem::offset_of!(PBKDF2_SHA256_Salt, salt) + salt_len, 0u8);
					let salt_buf = &mut *(salt_buffer.as_mut_ptr() as *mut PBKDF2_SHA256_Salt);
					salt_buf.length = salt_len as u32;
					std::ptr::copy_nonoverlapping(case.salt.as_ptr(), salt_buf.salt.as_mut_ptr(), salt_len);
				}

				let pbcfg = &mut *ctx.pbkdf2_sha256_config.borrow_mut();
				let cracks = &mut *ctx.pbkdf2_sha256_cracks.borrow_mut();
				let states = &mut *ctx.pbkdf2_sha256_states.borrow_mut();

				unsafe
				{
					let cfg = PBKDF2_SHA256_Config { rounds: 1, skip_bytes: 0, outlen: scrypt_key_len };
					if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, pbcfg, &[])?; }
					pbcfg.copy_from_slice(&[cfg]);
					if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_unmap(pbcfg, &[]).map_err(|e| e.to_string())?; }
				}

				let event = unsafe
				{
					let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_init_krnl.krnl);
					kernel.set_arg_svm(passes.as_ptr())
						.set_arg_svm(salt.as_mut_ptr())
						.set_arg_svm(pbcfg.as_mut_ptr())
						.set_arg_svm(states.as_mut_ptr());
					let event = kernel.set_global_work_size(passes_this_time)
						.enqueue_nd_range(&ctx.queue).map_err(|e| e.to_string())?;
					event
				};
				event.wait().map_err(|e| e.to_string())?;

				for derive_iter in 0..total_derivations
				{
					//since it is known we only got 1 iteration here, we don't need inner loop
					{
						let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_loop_krnl.krnl);
						let event = unsafe
						{
							kernel.set_arg_svm(states.as_mut_ptr())
								.set_global_work_size(passes_this_time)
								.enqueue_nd_range(&ctx.queue).map_err(|e| e.to_string())?
						};
						ctx.queue.finish().map_err(|e| e.to_string())?;
						event.wait().map_err(|e| e.to_string())?;
					}

					let event = unsafe
					{
						let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_final_krnl.krnl);
						kernel.set_arg_svm(cracks.as_mut_ptr())
							.set_arg_svm(salt.as_mut_ptr())
							.set_arg_svm(pbcfg.as_mut_ptr())
							.set_arg_svm(states.as_mut_ptr());
						let event = kernel.set_global_work_size(passes_this_time)
							.enqueue_nd_range(&ctx.queue).map_err(|e| e.to_string())?;
						event
					};

					event.wait().map_err(|e| e.to_string())?;

					let copy_offset = (derive_iter * 32) as usize;
					let to_copy = std::cmp::min(std::cmp::max(scrypt_key_len as usize, copy_offset) - copy_offset, 32);
					if !cracks.is_fine_grained() { unsafe { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_READ, cracks, &[])? }; }
					let cracks_local = cracks[..passes_this_time].to_vec();
					if !cracks.is_fine_grained() { unsafe { ctx.queue.enqueue_svm_unmap(cracks, &[]).map_err(|e| e.to_string())? }; }

					for i in 0..passes_this_time
					{
						let cracked = &cracks_local[i];
						let key = &mut derived_keys[i];
						unsafe { std::ptr::copy_nonoverlapping(cracked.digest.as_ptr(), key[copy_offset..(copy_offset+to_copy)].as_mut_ptr(), to_copy); }
					}

					//check if we have to prepare for next derivation
					let next_derive = derive_iter + 1;
					if next_derive != total_derivations
					{
						unsafe
						{
							let cfg = PBKDF2_SHA256_Config { rounds: 1, skip_bytes: next_derive * 32, outlen: scrypt_key_len };
							if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, pbcfg, &[])?; }
							pbcfg.copy_from_slice(&[cfg]);
							if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_unmap(pbcfg, &[]).map_err(|e| e.to_string())?; }
						}
					}
				}

				//okay so now we call romix function, thing is that romix function was designed the way to prevent it from running on GPU efficiently
				//so there will be much less iterations for romix function than for pbkdf2, there also will be less iterations for pbkdf2 functions which will be run right after the romix function
				debug_assert!(ctx.scrypt_iters != 0);
				let iters_over_romix = (passes_this_time + ctx.scrypt_iters - 1) / ctx.scrypt_iters;
				total_derivations = (ctx.keylen + 31) / 32;
				let to_derive = derived_keys.len();
				let mut real_keys_offset = to_derive;

				for rd in 0..iters_over_romix
				{
					//perform romix iterations, however in this case it will be a little bit different
					//we will have inner P loop and only process part of the keys per time
					//this is because romix function requires a lot of memory for V blocks computation
					//and there as many V blocks as N so it will be very memory-expensive
					let keys_derived = rd * ctx.scrypt_iters;
					let keys_this_time = std::cmp::min(to_derive - keys_derived, ctx.scrypt_iters);
					let remaining = derived_keys.split_off(keys_this_time);
					let mut keys_to_use = std::mem::replace(&mut derived_keys, remaining);
					real_keys_offset -= keys_this_time;
					derived_keys.resize_with(derived_keys.len() + keys_this_time, || { let mut v = Vec::<u8>::with_capacity(scrypt_key_len as usize); v.resize(scrypt_key_len as usize, 0u8); v });

					for p in 0..case.p
					{
						//set the X now
						unsafe
						{
							if !scrypt_block_X.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, scrypt_block_X, &[]).map_err(|e| e.to_string())?; }
							let x_arg = scrypt_block_X.as_mut_ptr();
							for i in 0..keys_this_time
							{
								let arg = x_arg.offset(i as isize);
								let key = &keys_to_use[i];
								let data = &key[(p * scrypt_block_size) as usize..];
								std::ptr::copy_nonoverlapping(data.as_ptr(), arg as *mut u8, scrypt_block_size as usize);
							}
							if !scrypt_block_X.is_fine_grained() { ctx.queue.enqueue_svm_unmap(scrypt_block_X, &[]).map_err(|e| e.to_string())?; }
						}

						let event = unsafe
						{
							let mut kernel = ExecuteKernel::new(&romix_krnl.krnl);
							kernel.set_arg(&(case.n as cl_int))
								.set_arg_svm(scrypt_block_X.as_mut_ptr())
								.set_arg_svm(scrypt_block_V.as_mut_ptr())
								.set_arg_svm(scrypt_block_X.as_mut_ptr());
							let event = kernel.set_global_work_size(keys_this_time)
								.enqueue_nd_range(&ctx.queue).map_err(|e| e.to_string())?;
							event
						};
						event.wait().map_err(|e| e.to_string())?;

						//store the results to the keys now
						unsafe
						{
							if !scrypt_block_X.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_READ, scrypt_block_X, &[]).map_err(|e| e.to_string())?; }
							let x_arg = scrypt_block_X.as_ptr();
							for i in 0..keys_this_time
							{
								let arg = x_arg.offset(i as isize);
								let key = &mut keys_to_use[i];
								let data = &mut key[(p * scrypt_block_size) as usize..];
								std::ptr::copy_nonoverlapping(arg as *const u8, data.as_mut_ptr(), scrypt_block_size as usize);
							}
							if !scrypt_block_X.is_fine_grained() { ctx.queue.enqueue_svm_unmap(scrypt_block_X, &[]).map_err(|e| e.to_string())?; }
						}
					}

					let store_offset = keys_derived + real_keys_offset;
					for i in 0..keys_this_time
					{
						let keyfrom = &keys_to_use[i];
						let keyto = &mut derived_keys[store_offset + i];
						debug_assert_eq!(keyfrom.len(), keyto.len());
						unsafe { std::ptr::copy_nonoverlapping(keyfrom.as_ptr(), keyto.as_mut_ptr(), keyfrom.len()); }
					}
				}

				//and now perform pbkdf2 iterations with the new data
				//but in this case we have salt per instance case, the keys_to_use vector now contains our salts
				unsafe
				{
					if !passes.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, passes, &[])?; }
					std::ptr::copy_nonoverlapping(passwords.as_ptr(), passes.as_mut_ptr(), passes_this_time);
					if !passes.is_fine_grained() { ctx.queue.enqueue_svm_unmap(passes, &[]).map_err(|e| e.to_string())?; }

					let mut salt_buffer = Vec::<u8>::new();
					let salt_size = std::mem::offset_of!(PBKDF2_SHA256_Salt, salt) + scrypt_key_len as usize;
					salt_buffer.resize(salt_size * passes_this_time, 0u8);
					let salt_buf = salt_buffer.as_mut_ptr();

					for i in 0..passes_this_time
					{
						let salt_buf = &mut *(salt_buf.offset((i * salt_size) as isize) as *mut PBKDF2_SHA256_Salt);
						let key = &mut derived_keys[i];
						salt_buf.length = scrypt_key_len;
						std::ptr::copy_nonoverlapping(key.as_ptr(), salt_buf.salt.as_mut_ptr(), scrypt_key_len as usize);
					}

					//copy the buffer now
					if !salt.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, salt, &[])?; }
					std::ptr::copy_nonoverlapping(salt_buf as *const u8, salt.as_mut_ptr(), salt_size * passes_this_time);
					if !salt.is_fine_grained() { ctx.queue.enqueue_svm_unmap(salt, &[]).map_err(|e| e.to_string())?; }
				}

				//resize derived keys now to match the actual derived key length
				derived_keys.iter_mut().map(|v| v.resize(ctx.keylen as usize, 0u8)).all(|_| true);

				unsafe
				{
					let cfg = PBKDF2_SHA256_Config { rounds: 1, skip_bytes: 0, outlen: keylen as u32 };
					if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, pbcfg, &[])?; }
					pbcfg.copy_from_slice(&[cfg]);
					if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_unmap(pbcfg, &[]).map_err(|e| e.to_string())?; }
				}

				let event = unsafe
				{
					let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_init_pi_krnl.krnl);
					kernel.set_arg_svm(passes.as_ptr())
						.set_arg_svm(salt.as_mut_ptr())
						.set_arg_svm(pbcfg.as_mut_ptr())
						.set_arg_svm(states.as_mut_ptr());
					let event = kernel.set_global_work_size(passes_this_time)
						.enqueue_nd_range(&ctx.queue).map_err(|e| e.to_string())?;
					event
				};
				event.wait().map_err(|e| e.to_string())?;

				for derive_iter in 0..total_derivations
				{
					//since it is known we only got 1 iteration here, we don't need inner loop
					{
						let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_loop_pi_krnl.krnl);
						let event = unsafe
						{
							kernel.set_arg_svm(states.as_mut_ptr())
								.set_global_work_size(passes_this_time)
								.enqueue_nd_range(&ctx.queue).map_err(|e| e.to_string())?
						};
						ctx.queue.finish().map_err(|e| e.to_string())?;
						event.wait().map_err(|e| e.to_string())?;
					}

					let event = unsafe
					{
						let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_final_pi_krnl.krnl);
						kernel.set_arg_svm(cracks.as_mut_ptr())
							.set_arg_svm(salt.as_mut_ptr())
							.set_arg_svm(pbcfg.as_mut_ptr())
							.set_arg_svm(states.as_mut_ptr());
						let event = kernel.set_global_work_size(passes_this_time)
							.enqueue_nd_range(&ctx.queue).map_err(|e| e.to_string())?;
						event
					};

					event.wait().map_err(|e| e.to_string())?;

					let copy_offset = (derive_iter * 32) as usize;
					let to_copy = std::cmp::min(std::cmp::max(keylen, copy_offset) - copy_offset, 32);
					if !cracks.is_fine_grained() { unsafe { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_READ, cracks, &[])? }; }
					let cracks_local = cracks[..passes_this_time].to_vec();
					if !cracks.is_fine_grained() { unsafe { ctx.queue.enqueue_svm_unmap(cracks, &[]).map_err(|e| e.to_string())? }; }

					for i in 0..passes_this_time
					{
						let cracked = &cracks_local[i];
						let key = &mut derived_keys[i];
						unsafe { std::ptr::copy_nonoverlapping(cracked.digest.as_ptr(), key[copy_offset..(copy_offset+to_copy)].as_mut_ptr(), to_copy); }
					}

					//check if we have to prepare for next derivation
					let next_derive = derive_iter + 1;
					if next_derive != total_derivations
					{
						unsafe
						{
							let cfg = PBKDF2_SHA256_Config { rounds: 1, skip_bytes: next_derive * 32, outlen: keylen as u32 };
							if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, pbcfg, &[])?; }
							pbcfg.copy_from_slice(&[cfg]);
							if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_unmap(pbcfg, &[]).map_err(|e| e.to_string())?; }
						}
					}
				}
			},
			OPT_PBKDF2_SPHS256_Case::PBKDF2(case) =>
			{
				//in this case we use kernels with one shared constant salt
				let pbkdf2_sha256_init_krnl = ctx.pbkdf2_sha256_init_krnl;
				let pbkdf2_sha256_loop_krnl = ctx.pbkdf2_sha256_loop_krnl;
				let pbkdf2_sha256_final_krnl = ctx.pbkdf2_sha256_final_krnl;
				let loops = (case.iterations + HASH_LOOPS_SHA256 - 1) / HASH_LOOPS_SHA256;
				let total_derivations = (ctx.keylen + 31) / 32;

				let passes = &mut *ctx.pbkdf2_sha256_passes.borrow_mut();
				let salt = &mut *ctx.pbkdf2_sha256_salt_svm.borrow_mut();

				unsafe
				{
					if !passes.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, passes, &[])?; }
					std::ptr::copy_nonoverlapping(passwords.as_ptr(), passes.as_mut_ptr(), passes_this_time);
					if !passes.is_fine_grained() { ctx.queue.enqueue_svm_unmap(passes, &[]).map_err(|e| e.to_string())?; }

					let salt_len = case.salt.len();
					let mut salt_buffer = Vec::<u8>::new();
					salt_buffer.resize(std::mem::offset_of!(PBKDF2_SHA256_Salt, salt) + salt_len, 0u8);
					let salt_buf = &mut *(salt_buffer.as_mut_ptr() as *mut PBKDF2_SHA256_Salt);
					salt_buf.length = salt_len as u32;
					std::ptr::copy_nonoverlapping(case.salt.as_ptr(), salt_buf.salt.as_mut_ptr(), salt_len);
				}

				let pbcfg = &mut *ctx.pbkdf2_sha256_config.borrow_mut();
				let cracks = &mut *ctx.pbkdf2_sha256_cracks.borrow_mut();
				let states = &mut *ctx.pbkdf2_sha256_states.borrow_mut();

				unsafe
				{
					let cfg = PBKDF2_SHA256_Config { rounds: case.iterations, skip_bytes: 0, outlen: ctx.keylen };
					if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, pbcfg, &[])?; }
					pbcfg.copy_from_slice(&[cfg]);
					if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_unmap(pbcfg, &[]).map_err(|e| e.to_string())?; }
				}

				let event = unsafe
				{
					let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_init_krnl.krnl);
					kernel.set_arg_svm(passes.as_ptr())
						.set_arg_svm(&salt.as_mut_ptr())
						.set_arg_svm(&pbcfg.as_mut_ptr())
						.set_arg_svm(states.as_mut_ptr());
					let event = kernel.set_global_work_size(passes_this_time)
						.enqueue_nd_range(&ctx.queue).map_err(|e| e.to_string())?;
					event
				};
				event.wait().map_err(|e| e.to_string())?;

				derived_keys.resize_with(passwords.len(), || { let mut v = Vec::<u8>::with_capacity(keylen); v.resize(keylen, 0u8); v } );
				for derive_iter in 0..total_derivations
				{
					{
						let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_loop_krnl.krnl);
						for _ in 0..loops
						{
							let event = unsafe
							{
								kernel.set_arg_svm(states.as_mut_ptr())
									.set_global_work_size(passes_this_time)
									.enqueue_nd_range(&ctx.queue).map_err(|e| e.to_string())?
							};
							ctx.queue.finish().map_err(|e| e.to_string())?;
							event.wait().map_err(|e| e.to_string())?;
						}
					}

					let event = unsafe
					{
						let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_final_krnl.krnl);
						kernel.set_arg_svm(cracks.as_mut_ptr())
							.set_arg_svm(&salt.as_mut_ptr())
							.set_arg_svm(&pbcfg.as_mut_ptr())
							.set_arg_svm(states.as_mut_ptr());
						let event = kernel.set_global_work_size(passes_this_time)
							.enqueue_nd_range(&ctx.queue).map_err(|e| e.to_string())?;
						event
					};

					event.wait().map_err(|e| e.to_string())?;

					let copy_offset = (derive_iter * 32) as usize;
					let to_copy = std::cmp::min(std::cmp::max(keylen, copy_offset) - copy_offset, 32);
					if !cracks.is_fine_grained() { unsafe { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_READ, cracks, &[])? }; }
					let cracks_local = cracks[..passes_this_time].to_vec();
					if !cracks.is_fine_grained() { unsafe { ctx.queue.enqueue_svm_unmap(cracks, &[]).map_err(|e| e.to_string())? }; }

					for i in 0..passes_this_time
					{
						let cracked = &cracks_local[i];
						let key = &mut derived_keys[i];
						unsafe { std::ptr::copy_nonoverlapping(cracked.digest.as_ptr(), key[copy_offset..(copy_offset+to_copy)].as_mut_ptr(), to_copy); }
					}

					//check if we have to prepare for next derivation
					let next_derive = derive_iter + 1;
					if next_derive != total_derivations
					{
						unsafe
						{
							let cfg = PBKDF2_SHA256_Config { rounds: case.iterations, skip_bytes: next_derive * 32, outlen: ctx.keylen };
							if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, pbcfg, &[])?; }
							pbcfg.copy_from_slice(&[cfg]);
							if !pbcfg.is_fine_grained() { ctx.queue.enqueue_svm_unmap(pbcfg, &[]).map_err(|e| e.to_string())?; }
						}
					}
				}
			}
		}

		let keccak256_input = &mut *ctx.keccak256_input.borrow_mut();
		let keccak256_output = &mut *ctx.keccak256_output.borrow_mut();

		//now perform keccak256 hashes on data with derived keys
		//for that copy the key to the prepared space with data after it and then pass it to the kernel
		let keysize = ctx.keysize as usize;
		let data_len_with_key = ctx.data.len() + keylen - keysize;
		let key_offset = (keylen - keysize) as isize;
		unsafe
		{
			if !keccak256_input.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, keccak256_input, &[]).map_err(|e| e.to_string())?; }
			for i in 0..passes_this_time
			{
				let key = &derived_keys[i];
				let ptr = keccak256_input.as_mut_ptr().offset((data_len_with_key * i) as isize);
				std::ptr::copy_nonoverlapping(key.as_ptr().offset(key_offset), ptr, keylen - key_offset as usize);
			}
			if !keccak256_input.is_fine_grained() { ctx.queue.enqueue_svm_unmap(keccak256_input, &[]).map_err(|e| e.to_string())?; }
		}

		let event = unsafe
		{
			let mut kernel = ExecuteKernel::new(&keccak256_krnl.krnl);
			kernel.set_arg_svm(keccak256_input.as_mut_ptr())
				.set_arg(&(data_len_with_key as cl_uint))
				.set_arg_svm(keccak256_output.as_mut_ptr());
			let event = kernel.set_global_work_size(passes_this_time)
				.enqueue_nd_range(&ctx.queue).map_err(|e| e.to_string())?;
			event
		};

		event.wait().map_err(|e| e.to_string())?;

		//check the results now, if any matches to the MAC, then we found the key yay!
		let macs_size = 32 * passes_this_time;
		let mut macs = Vec::<u8>::with_capacity(macs_size);
		macs.resize(macs_size, 0u8);
		unsafe
		{
			if !keccak256_output.is_fine_grained() { ctx.queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_READ, keccak256_output, &[]).map_err(|e| e.to_string())?; }
			std::ptr::copy_nonoverlapping(keccak256_output.as_ptr(), macs.as_mut_ptr(), macs_size);
			if !keccak256_output.is_fine_grained() { ctx.queue.enqueue_svm_unmap(keccak256_output, &[]).map_err(|e| e.to_string())?; }
		}

		//check if any matches
		for i in 0..passes_this_time
		{
			let offset = i * 32;
			let mac = &macs[offset..offset+32];
			if mac == ctx.mac
			{
				//at this point try to decrypt
				let key = &derived_keys[i];
				use aes::cipher::{ KeyIvInit, StreamCipher };
				let mut decryptor: Box<dyn StreamCipher> = match ctx.cipher
				{
					OPT_PBKDF2_SPHS256_Cipher::AES_CTR_128 => Box::new(ctr::Ctr128BE::<aes::Aes128>::new(key[..keysize].try_into().unwrap(), ctx.iv[..16].try_into().unwrap())),
					OPT_PBKDF2_SPHS256_Cipher::AES_CTR_192 => Box::new(ctr::Ctr128BE::<aes::Aes192>::new(key[..keysize].try_into().unwrap(), ctx.iv[..16].try_into().unwrap())),
					OPT_PBKDF2_SPHS256_Cipher::AES_CTR_256 => Box::new(ctr::Ctr128BE::<aes::Aes256>::new(key[..keysize].try_into().unwrap(), ctx.iv[..16].try_into().unwrap())),
				};

				let mut data_copy = ctx.data.clone();
				decryptor.apply_keystream(&mut data_copy);
				let decrypted_data = String::from_utf8(data_copy);
				if let Ok(actual_data) = decrypted_data
				{
					//it is very unlikely in case of collision that the decrypted data also will be valid UTF-8 data considering its size
					//so guess the data is valid, this should be enough
					let password;
					match ctx.original_passwords
					{
						OrigPasses::PBKDF2_SHA256(pwd) =>
						{
							let pass = &pwd[i];
							let len = pass.length as usize;
							password = String::from_utf8_lossy(&pass.v[..len]).into_owned();
						},
						OrigPasses::PBKDF2_SHA512(pwd) =>
						{
							let pass = &pwd[i];
							let len = pass.length as usize;
							password = String::from_utf8_lossy(&pass.v[..len]).into_owned();
						}
					}

					return Ok(Some((actual_data, password)));
				}
			}
		}

		Ok(None)
	}

	fn PK2S512SCPK2S256KACC_BruteforceCPUWithPass(data: &Vec<u8>, iv: &Vec<u8>, mac: &[u8; 32], kdf: &OPT_PBKDF2_SPHS256_Case, keylen: u32, cipher: OPT_PBKDF2_SPHS256_Cipher, password: &String) -> Result<Option<(String, String)>, String>
	{
		use aes::cipher::{ KeyIvInit, StreamCipher };
		let mut derived_key = Vec::<u8>::new();
		let keylen = keylen as usize;
		derived_key.resize(keylen, 0u8);

		match kdf
		{
			OPT_PBKDF2_SPHS256_Case::SCrypt(data) =>
			{
				let params = rust_scrypt::ScryptParams{ n: data.n, r: data.r, p: data.p };
				rust_scrypt::scrypt(password.as_bytes(), &data.salt, &params, &mut derived_key);
			},
			OPT_PBKDF2_SPHS256_Case::PBKDF2(data) =>
			{
				fastpbkdf2::pbkdf2_hmac_sha256(password.as_bytes(), &data.salt, data.iterations, &mut derived_key);
			}
		}

		let keysize = match cipher
		{
			OPT_PBKDF2_SPHS256_Cipher::AES_CTR_128 => 16usize,
			OPT_PBKDF2_SPHS256_Cipher::AES_CTR_192 => 24usize,
			OPT_PBKDF2_SPHS256_Cipher::AES_CTR_256 => 32usize,
		};

		//check the mac now, if it matches, then we can decrypt
		use tiny_keccak::Hasher;
		let mut computed_mac = [0u8; 32];
		let mut keccak = tiny_keccak::Keccak::v256();
		keccak.update(&derived_key[keylen-keysize..]);
		keccak.update(data);
		keccak.finalize(&mut computed_mac);
		if &computed_mac != mac { return Ok(None); }

		let mut decryptor: Box<dyn StreamCipher> = match cipher
		{
			OPT_PBKDF2_SPHS256_Cipher::AES_CTR_128 => Box::new(ctr::Ctr128BE::<aes::Aes128>::new(derived_key[..keysize].try_into().unwrap(), iv[..16].try_into().unwrap())),
			OPT_PBKDF2_SPHS256_Cipher::AES_CTR_192 => Box::new(ctr::Ctr128BE::<aes::Aes192>::new(derived_key[..keysize].try_into().unwrap(), iv[..16].try_into().unwrap())),
			OPT_PBKDF2_SPHS256_Cipher::AES_CTR_256 => Box::new(ctr::Ctr128BE::<aes::Aes256>::new(derived_key[..keysize].try_into().unwrap(), iv[..16].try_into().unwrap())),
		};

		let mut data_copy = data.clone();
		decryptor.apply_keystream(&mut data_copy);
		let decrypted_data = String::from_utf8(data_copy);
		if let Ok(actual_data) = decrypted_data
		{
			//it is very unlikely in case of collision that the decrypted data also will be valid UTF-8 data considering its size
			//so guess the data is valid, this should be enough
			return Ok(Some((actual_data, password.clone())));
		}

		//some invalid bullshit was there. Probably MAC collision...
		Ok(None)
	}
}