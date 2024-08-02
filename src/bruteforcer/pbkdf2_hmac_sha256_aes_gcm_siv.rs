use super::*;
use super::algs::{ pbkdf2::*, aesgcm::* };
use opencl3::program::CL_STD_2_0;
use opencl3::command_queue::CommandQueue;
use opencl3::kernel::ExecuteKernel;
use opencl3::svm::SvmVec;
use opencl3::types::{ cl_uint, CL_BLOCKING };
use opencl3::memory::{ Buffer, ClMem, CL_MAP_READ, CL_MAP_WRITE, CL_MEM_COPY_HOST_PTR, CL_MEM_HOST_NO_ACCESS, CL_MEM_READ_ONLY };
use std::{ ffi::c_void, sync::Mutex };
use std::alloc::{ alloc, dealloc, Layout };

pub struct PBKDF2_AES_GCM_SIV_Request
{
	pub data: Vec<u8>,
	pub iv: [u8; 12],
	pub salt: Vec<u8>,
	pub iterations: u32,
}

pub trait PBKDF2_AES_GCM_SIV
{
	fn PK2AGS_BruteforceCPU(req: &PBKDF2_AES_GCM_SIV_Request, passwords: &Vec<String>) -> Result<Option<(String, String)>, String>;
	fn PK2AGS_BruteforceGPU(devices: Arc<Vec<GPUDeviceInfo>>, gpupg: Arc<OpenCLProgram>, req: &PBKDF2_AES_GCM_SIV_Request, passwords: &Vec<String>) -> Result<Option<(String, String)>, String>;
	fn PK2AGS_LoadKernels(devices: &Arc<Vec<GPUDeviceInfo>>) -> Result<OpenCLProgram, String>;
}

impl PBKDF2_AES_GCM_SIV for BruteForcer
{
	fn PK2AGS_BruteforceCPU(req: &PBKDF2_AES_GCM_SIV_Request, passwords: &Vec<String>) -> Result<Option<(String, String)>, String>
	{
		//to perform CPU bruteforce we use fastpbkdf2 crate and aes-gcm crate
		use aes_gcm_siv::{ aead::KeyInit, Aes256GcmSiv, Nonce, Key, Tag };
		use aead::AeadMutInPlace;

		let mut req_data = req.data.clone();
		let nonce = Nonce::from_slice(&req.iv);
		let tag_data = req_data.split_off(req_data.len() - 16);
		let tag = Tag::from_slice(&tag_data);
		let mut aes_key = [0u8; 32];

		for possible_pass in passwords
		{
			//metamask uses fastpbkdf2 with hmac<sha256>
			//the result of pbkdf2 function is the aes key
			//then we use the key to try to decrypt the req, if it succeedes, then we signal about that
			fastpbkdf2::pbkdf2_hmac_sha256(possible_pass.as_bytes(), &req.salt, req.iterations, &mut aes_key);

			//try to decrypt now
			let mut decryptor = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(&aes_key));
			let mut data_copy = req_data.clone();
			if let Ok(_) = decryptor.decrypt_in_place_detached(nonce, b"", &mut data_copy, tag)
			{
				//we found it! Signal that we found the needed password
				let json = String::from_utf8(data_copy);
				if let Ok(actual_data) = json
				{
					//it is very unlikely in case of collision that the decrypted data also will be valid UTF-8 data considering its size
					//so guess the data is valid, this should be enough
					return Ok(Some((actual_data, possible_pass.clone())));
				}
			}
		}

		Ok(None)
	}

	fn PK2AGS_BruteforceGPU(devices: Arc<Vec<GPUDeviceInfo>>, gpupg: Arc<OpenCLProgram>, req: &PBKDF2_AES_GCM_SIV_Request, passwords: &Vec<String>) -> Result<Option<(String, String)>, String>
	{
		//by specifying 0 we let the device to decide which queue size to use
		//https://registry.khronos.org/OpenCL/sdk/3.0/docs/man/html/clCreateCommandQueueWithProperties.html
		let queue = CommandQueue::create_default_with_properties(&gpupg.ctx, 0, 0).map_err(|e| e.to_string())?;
		let max_mem_per_queue = devices.iter().map(|d| d.max_memory_alloc as usize).collect::<Vec<_>>().into_iter().min().unwrap_or(0);
		if max_mem_per_queue == 0 { return Err("Unexpected max memory value".to_owned()); }

		let pbkdf2_sha256_init_krnl = WrappedKernel::clone(gpupg.krnls.get("pbkdf2_sha256_init").unwrap());
		let pbkdf2_sha256_loop_krnl = WrappedKernel::clone(gpupg.krnls.get("pbkdf2_sha256_loop").unwrap());
		let pbkdf2_sha256_final_krnl = WrappedKernel::clone(gpupg.krnls.get("pbkdf2_sha256_final").unwrap());
		let aes_gcmsiv_decrypt_and_check_krnl = WrappedKernel::clone(gpupg.krnls.get("aes_gcmsiv_decrypt_and_check").unwrap());

		//find out how many pbkdf passes per iter we actually can handle
		let max_global_work_size = vec![pbkdf2_sha256_init_krnl.mgws, pbkdf2_sha256_loop_krnl.mgws, pbkdf2_sha256_final_krnl.mgws, passwords.len()].into_iter().min().unwrap_or(0);
		if max_global_work_size == 0 { return Err("Unexpected global work size (pbkdf2)".to_owned()); }
		
		//ensure limits ain't violated (this is edge case, may happen on some weak GPU's or if encrypted data is too big (gcm case))
		let data_len_without_tag = req.data.len() - 16;
		let size_of_salt = std::mem::offset_of!(PBKDF2_SHA256_Salt, salt) + req.salt.len();
		let max_arg_size = devices.iter().map(|d| d.max_single_argument_size as usize).collect::<Vec<_>>().into_iter().min().unwrap_or(0);
		if max_arg_size < std::mem::size_of::<PBKDF2_SHA256_State>() ||
			max_arg_size < std::mem::size_of::<PBKDF2_SHA256_Pass>() ||
			max_arg_size < std::mem::size_of::<PBKDF2_SHA256_Crack>() ||
			max_arg_size < size_of_salt ||
			max_arg_size < std::mem::size_of::<PBKDF2_SHA256_Config>() ||
			max_arg_size < std::mem::size_of::<AESGCM_Key>() ||
			max_arg_size < std::mem::size_of::<AESGCM_SIV>() ||
			max_arg_size < std::mem::size_of::<AESGCM_AEAD>() ||
			max_arg_size < std::mem::size_of::<AESGCM_TAG>() ||
			max_arg_size < data_len_without_tag
		{
			return Err("Too little memory for an argument".to_owned());
		}

		//take valid passwords here
		#[allow(deref_nullptr)]
		let mut pwds = passwords.iter().filter_map(|p| if p.len() <= unsafe { std::mem::size_of_val_raw( &raw const (*std::ptr::null::<PBKDF2_SHA256_Pass>()).v) }
		{
			let plen = p.len();
			let mut r = PBKDF2_SHA256_Pass
			{
				length: plen as u32,
				v: unsafe { std::mem::MaybeUninit::uninit().assume_init() }
			};
			r.v[..plen].copy_from_slice(p.as_bytes());
			Some(r)
		} else { None }).collect::<Vec<_>>();

		if pwds.len() == 0
		{ return Err("No valid passwords to use in bruteforce".to_owned()); }

		//how many we can allocate per request?
		let total_request_size_no_salt = std::mem::size_of::<PBKDF2_SHA256_State>() +
			std::mem::size_of::<PBKDF2_SHA256_Pass>() +
			std::mem::size_of::<PBKDF2_SHA256_Crack>();
		
		let total_mem_no_salt = pwds.len() * total_request_size_no_salt;
		let total_iters_no_salt = (total_mem_no_salt + max_mem_per_queue - 1) / max_mem_per_queue;
		let total_iters_with_salt = (total_mem_no_salt + (total_iters_no_salt * size_of_salt) + max_mem_per_queue - 1) / max_mem_per_queue;
		debug_assert!(total_iters_with_salt >= total_iters_no_salt);

		let total_passes_per_iter = std::cmp::min((max_mem_per_queue - std::cmp::min(max_mem_per_queue, size_of_salt)) / total_request_size_no_salt, max_global_work_size);
		if total_passes_per_iter == 0 { return Err("Unexpected passes per iteration amount (pbkdf2)".to_owned()); }

		//now, how many aes passes we can perform per pbkdf2 iteration?
		let total_aes_pass_size_no_static_data = std::mem::size_of::<AESGCM_Key>() + std::mem::size_of::<cl_uint>();
		let total_aes_static_data_size = std::mem::size_of::<AESGCM_TAG>() + std::mem::size_of::<AESGCM_SIV>() + std::mem::size_of::<AESGCM_AEAD>() + std::mem::size_of::<cl_uint>() + req.data.len();
		let total_aes_passes_per_iter_with_static_data = (max_mem_per_queue - std::cmp::min(total_aes_static_data_size, max_mem_per_queue)) / total_aes_pass_size_no_static_data;
		let total_aes_passes_clamped = vec![total_aes_passes_per_iter_with_static_data, total_passes_per_iter, aes_gcmsiv_decrypt_and_check_krnl.mgws].into_iter().min().unwrap_or(0);
		if total_aes_passes_clamped == 0 { return Err("Unexpected passes per iteration amount (aes)".to_owned()); }
		let total_aes_iters_per_pbkdf2_iter = (total_aes_passes_clamped + total_passes_per_iter - 1) / total_passes_per_iter;

		//at first we want to bruteforce all the passwords, then we gonna test them against gcm tag
		//the one which succeedes is our potential answer, we handle tag collisions by checking
		//if the decrypted data can be decoded as UTF-8 (and better as json), then the data is correct for sure
		let mut states = SvmVec::<PBKDF2_SHA256_State>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?;
		let mut passes = SvmVec::<PBKDF2_SHA256_Pass>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?;
		let mut cracks = SvmVec::<PBKDF2_SHA256_Crack>::allocate(&gpupg.ctx, total_passes_per_iter).map_err(|e| e.to_string())?;
		let mut aes_key = SvmVec::<AESGCM_Key>::allocate(&gpupg.ctx, total_aes_passes_clamped).map_err(|e| e.to_string())?;
		let mut aes_results_data = SvmVec::<cl_uint>::allocate(&gpupg.ctx, total_aes_passes_clamped).map_err(|e| e.to_string())?;
		
		//now we have to prepare some data to create constant buffers
		let mut req_data = req.data.clone();
		let tag_data = req_data.split_off(data_len_without_tag);
		let req_data_single_size = req_data.len();

		if total_aes_passes_clamped > 1
		{
			req_data.reserve_exact(req_data.len() * (total_aes_passes_clamped - 1));
			for _ in 1..total_aes_passes_clamped { req_data.extend_from_within(..req_data_single_size); }
		}

		let mut aes_crypt_data = SvmVec::<u8>::allocate(&gpupg.ctx, req_data.len()).map_err(|e| e.to_string())?;

		let salt;
		let pbcfg;
		let aes_iv;
		let aes_aead;
		let aes_tag;
		{
			let req_salt_len = req.salt.len();
			let salt_buffer;
			let salt_layout;
			let salt_size;
			unsafe
			{
				let salt_align = std::mem::align_of::<PBKDF2_SHA256_Salt>();
				salt_size = (((std::mem::offset_of!(PBKDF2_SHA256_Salt, salt) + req_salt_len + 64) + salt_align - 1) / salt_align) * salt_align;
				salt_layout = Layout::from_size_align_unchecked(salt_size, salt_align);
				salt_buffer = alloc(salt_layout);
				if salt_buffer.is_null() { return Err("Unable to allocate salt buffer".to_owned()); }
				let salt_buf = &mut *(salt_buffer as *mut PBKDF2_SHA256_Salt);
				salt_buf.length = req_salt_len as u32;
				std::ptr::copy_nonoverlapping(req.salt.as_ptr(), salt_buf.salt.as_mut_ptr(), req_salt_len);
			}

			let mut pbcfg_buffer = PBKDF2_SHA256_Config
			{
				rounds: req.iterations,
				skip_bytes: 0,
				outlen: 32,
			};

			let mut iv_buffer = AESGCM_SIV { iv: req.iv };
			let mut tag_buffer = AESGCM_TAG { tag: tag_data.clone().try_into().unwrap() };

			let mut aead_buffer = AESGCM_AEAD
			{
				aead: unsafe { std::mem::MaybeUninit::uninit().assume_init() }, //we can leave this one uninited, we don't care about its content
				aead_len: 0,
			};
			
			unsafe 
			{
				let flags = CL_MEM_HOST_NO_ACCESS | CL_MEM_COPY_HOST_PTR | CL_MEM_READ_ONLY;
				match Buffer::<u8>::create(&gpupg.ctx, flags, salt_size, salt_buffer.cast::<c_void>()).map_err(|e| e.to_string())
				{
					Ok(r) => { salt = r; dealloc(salt_buffer, salt_layout); },
					Err(e) => { dealloc(salt_buffer, salt_layout); return Err(e); }
				}
				pbcfg = Buffer::<PBKDF2_SHA256_Config>::create(&gpupg.ctx, flags, 1, std::ptr::addr_of_mut!(pbcfg_buffer).cast::<c_void>()).map_err(|e| e.to_string())?;
				aes_iv = Buffer::<AESGCM_SIV>::create(&gpupg.ctx, flags, 1, std::ptr::addr_of_mut!(iv_buffer).cast::<c_void>()).map_err(|e| e.to_string())?;
				aes_aead = Buffer::<AESGCM_AEAD>::create(&gpupg.ctx, flags, 1, std::ptr::addr_of_mut!(aead_buffer).cast::<c_void>()).map_err(|e| e.to_string())?;
				aes_tag = Buffer::<AESGCM_TAG>::create(&gpupg.ctx, flags, 1, std::ptr::addr_of_mut!(tag_buffer).cast::<c_void>()).map_err(|e| e.to_string())?;
			}
		}

		//NOTE: we don't need to init cracks nor states, these can be dirty just fine
		//the same is true for aes result buffer

		let loops = (req.iterations + HASH_LOOPS_SHA256 - 1) / HASH_LOOPS_SHA256;
		for _ in 0..total_iters_with_salt
		{
			//fill our passwords buffer now, this is the only buffer we need to fill for pbkdf2 algorithm
			let passes_this_time = std::cmp::min(pwds.len(), total_passes_per_iter);
			let remaining = pwds.split_off(passes_this_time);
			let to_pass = std::mem::replace(&mut pwds, remaining);
			unsafe
			{
				if !passes.is_fine_grained() { queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, &mut passes, &[]).map_err(|e| e.to_string())?; }
				std::ptr::copy_nonoverlapping(to_pass.as_ptr(), passes.as_mut_ptr(), passes_this_time);
				if !passes.is_fine_grained() { queue.enqueue_svm_unmap(&passes, &[]).map_err(|e| e.to_string())?; }
			}

			let event = unsafe
			{
				//set_arg is not thread safe, so we have to lock here
				let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_init_krnl.krnl);
				// let guard = pbkdf2_sha256_init_krnl.mtx.lock();
				kernel.set_arg_svm(passes.as_ptr())
					.set_arg(&salt.get())
					.set_arg(&pbcfg.get())
					.set_arg_svm(states.as_mut_ptr());
				let event = kernel.set_global_work_size(passes_this_time)
					.enqueue_nd_range(&queue).map_err(|e| e.to_string())?;
				// std::mem::drop(guard);
				event
			};

			event.wait().map_err(|e| e.to_string())?;

			{
				let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_loop_krnl.krnl);
				for _ in 0..loops
				{
					let event = unsafe
					{
						kernel.set_arg_svm(states.as_mut_ptr())
							.set_global_work_size(passes_this_time)
							.enqueue_nd_range(&queue).map_err(|e| e.to_string())?
					};
					queue.finish().map_err(|e| e.to_string())?;
					event.wait().map_err(|e| e.to_string())?;
				}
			}

			let event = unsafe
			{
				let mut kernel = ExecuteKernel::new(&pbkdf2_sha256_final_krnl.krnl);
				// let guard = pbkdf2_sha256_final_krnl.mtx.lock();
				kernel.set_arg_svm(cracks.as_mut_ptr())
					.set_arg(&salt.get())
					.set_arg(&pbcfg.get())
					.set_arg_svm(states.as_mut_ptr());
				let event = kernel.set_global_work_size(passes_this_time)
					.enqueue_nd_range(&queue).map_err(|e| e.to_string())?;
				// std::mem::drop(guard);
				event
			};

			event.wait().map_err(|e| e.to_string())?;

			//read the hashes now and test them against aes-gcm
			if !cracks.is_fine_grained() { unsafe { queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_READ, &mut cracks, &[])? }; }
			let cracks_local = cracks[..passes_this_time].to_vec();
			if !cracks.is_fine_grained() { unsafe { queue.enqueue_svm_unmap(&cracks, &[]).map_err(|e| e.to_string())? }; }
			let mut keys = cracks_local.into_iter().map(|v| AESGCM_Key { key: v.digest, key_len: 32 }).collect::<Vec<_>>();

			for aes_iter in 0..total_aes_iters_per_pbkdf2_iter
			{
				let passes_this_time = std::cmp::min(keys.len(), total_aes_passes_clamped);
				if passes_this_time == 0 { break; } //maybe the case on last iteration

				let remaining = keys.split_off(passes_this_time);
				let this_time = std::mem::replace(&mut keys, remaining);

				unsafe
				{
					if !aes_key.is_fine_grained() { queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, &mut aes_key, &[])?; }
					std::ptr::copy_nonoverlapping(this_time.as_ptr(), aes_key.as_mut_ptr(), passes_this_time);
					if !aes_key.is_fine_grained() { queue.enqueue_svm_unmap(&aes_key, &[]).map_err(|e| e.to_string())?; }
					if !aes_crypt_data.is_fine_grained() { queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_WRITE, &mut aes_crypt_data, &[])?; }
					std::ptr::copy_nonoverlapping(req_data.as_ptr(), aes_crypt_data.as_mut_ptr(), req_data_single_size * passes_this_time);
					if !aes_crypt_data.is_fine_grained() { queue.enqueue_svm_unmap(&aes_crypt_data, &[]).map_err(|e| e.to_string())?; }
				}

				let event = unsafe
				{
					let mut kernel = ExecuteKernel::new(&aes_gcmsiv_decrypt_and_check_krnl.krnl);
					// let guard = aes_gcmsiv_decrypt_and_check_krnl.mtx.lock();
					kernel.set_arg_svm(aes_key.as_ptr())
						.set_arg(&aes_iv.get())
						.set_arg(&aes_tag.get())
						.set_arg(&aes_aead.get())
						.set_arg_svm(aes_crypt_data.as_mut_ptr())
						.set_arg(&(req_data_single_size as cl_uint))
						.set_arg_svm(aes_results_data.as_mut_ptr());
					let event = kernel.set_global_work_size(passes_this_time)
						.enqueue_nd_range(&queue).map_err(|e| e.to_string())?;
					// std::mem::drop(guard);
					event
				};

				queue.finish().map_err(|e| e.to_string())?;
				event.wait().map_err(|e| e.to_string())?;

				//check if anything found, if so, then check if for validness
				if !aes_results_data.is_fine_grained() { unsafe { queue.enqueue_svm_map(CL_BLOCKING, CL_MAP_READ, &mut aes_results_data, &[])? }; }
				let results = aes_results_data[..passes_this_time].to_vec();
				if !aes_results_data.is_fine_grained() { unsafe { queue.enqueue_svm_unmap(&aes_results_data, &[]).map_err(|e| e.to_string())? }; }
				for i in 0..passes_this_time
				{
					if results[i] == 0
					{
						//we found something at i, try to decrypt now, if the result is correct, then get out with it
						//I have copypasted it from CPU case which should be okay, for perfomance reasons we should not follow DRY here
						let key = this_time[i].key;
						use aes_gcm_siv::{ aead::KeyInit, Aes256GcmSiv, Nonce, Key, Tag };
						use aead::AeadMutInPlace;
						let nonce = Nonce::from_slice(&req.iv);
						let tag = Tag::from_slice(&tag_data);

						//try to decrypt now
						let mut decryptor = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(&key));
						let mut data_copy = req_data[..req_data_single_size].to_vec();
						if let Ok(_) = decryptor.decrypt_in_place_detached(nonce, b"", &mut data_copy, tag)
						{
							//we found it! Signal that we found the needed password
							let json = String::from_utf8(data_copy);
							if let Ok(actual_data) = json
							{
								//it is very unlikely in case of collision that the decrypted data also will be valid UTF-8 data considering its size
								//so guess the data is valid, this should be enough
								let pass_pos = aes_iter * total_aes_iters_per_pbkdf2_iter + i;
								let pass = to_pass[pass_pos];
								let pass_len = pass.length as usize;
								let password = String::from_utf8(pass.v[..pass_len].to_vec()).unwrap_or("".to_owned());
								return Ok(Some((actual_data, password)));
							}
						}
					}
				}
			}
		}
		
		Ok(None)
	}

	fn PK2AGS_LoadKernels(devices: &Arc<Vec<GPUDeviceInfo>>) -> Result<OpenCLProgram, String>
	{
		let devices_p = devices.iter().map(|d| d.device.id()).collect::<Vec<_>>();
		let context = Context::from_devices(&devices_p, &[], None, std::ptr::null_mut::<c_void>()).map_err(|e| e.to_string())?;

		let aes_gcm_siv_single = String::from_utf8(include_bytes!("./cl/aes_gcm_siv_single.cl").to_vec()).map_err(|e| e.to_string())?;
		let pbkdf2_hmac_sha256_single = String::from_utf8(include_bytes!("./cl/pbkdf2_hmac_sha256_single.cl").to_vec()).map_err(|e| e.to_string())?;
		let program1 = Program::create_and_build_from_source(&context, &pbkdf2_hmac_sha256_single, CL_STD_2_0).map_err(|e| e.to_string())?;
		let pbkdf2_sha256_init_krnl = Kernel::create(&program1, "pbkdf2_sha256_init").map_err(|e| e.to_string())?;
		let pbkdf2_sha256_loop_krnl = Kernel::create(&program1, "pbkdf2_sha256_loop").map_err(|e| e.to_string())?;
		let pbkdf2_sha256_final_krnl = Kernel::create(&program1, "pbkdf2_sha256_final").map_err(|e| e.to_string())?;

		let program2 = Program::create_and_build_from_source(&context, &aes_gcm_siv_single, CL_STD_2_0).map_err(|e| e.to_string())?;
		let aes_gcmsiv_decrypt_and_check_krnl = Kernel::create(&program2, "aes_gcmsiv_decrypt_and_check").map_err(|e| e.to_string())?;
		let program = vec![program1, program2];

		let pbkdf2_sha256_init_mgws = devices.iter().map(|d| pbkdf2_sha256_init_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let pbkdf2_sha256_loop_mgws = devices.iter().map(|d| pbkdf2_sha256_loop_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let pbkdf2_sha256_final_mgws = devices.iter().map(|d| pbkdf2_sha256_final_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);
		let aes_gcmsiv_decrypt_and_check_mgws = devices.iter().map(|d| aes_gcmsiv_decrypt_and_check_krnl.get_work_group_size(d.device.id()).unwrap_or(1)).collect::<Vec<_>>().into_iter().min().unwrap_or(1);

		let mut kernels = HashMap::new();
		kernels.insert("pbkdf2_sha256_init", WrappedKernel{ krnl: pbkdf2_sha256_init_krnl, mgws: pbkdf2_sha256_init_mgws, mtx: Mutex::new(()) });
		kernels.insert("pbkdf2_sha256_loop", WrappedKernel{ krnl: pbkdf2_sha256_loop_krnl, mgws: pbkdf2_sha256_loop_mgws, mtx: Mutex::new(()) });
		kernels.insert("pbkdf2_sha256_final", WrappedKernel{ krnl: pbkdf2_sha256_final_krnl, mgws: pbkdf2_sha256_final_mgws, mtx: Mutex::new(()) });
		kernels.insert("aes_gcmsiv_decrypt_and_check", WrappedKernel{ krnl: aes_gcmsiv_decrypt_and_check_krnl, mgws: aes_gcmsiv_decrypt_and_check_mgws, mtx: Mutex::new(()) });

		Ok(OpenCLProgram
		{
			ctx: context,
			pgs: program,
			krnls: kernels
		})
	}
}