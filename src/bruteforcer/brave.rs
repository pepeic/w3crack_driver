use super::*;
use base64::{ Engine as _, prelude::* };
use async_trait::async_trait;
use pbkdf2_hmac_sha256_aes_gcm_siv::{ PBKDF2_AES_GCM_SIV, PBKDF2_AES_GCM_SIV_Request };

#[derive(serde::Deserialize)]
struct BraveVault
{
	data: String,
	iv: String,
	salt: String,
	iterations: u32
}

trait BraveBruteforcerInternal
{
	fn BraveUnpackRequest(&mut self, vault: Vec<u8>) -> Result<BraveVault, String>;
	fn BraveVerifyVault(vault: BraveVault) -> Result<PBKDF2_AES_GCM_SIV_Request, String>;
}

#[allow(private_bounds)]
#[async_trait]
pub trait BraveBruteforcer : BraveBruteforcerInternal
{
	async fn HandleBrave(&mut self, vault: Vec<u8>, passwords: Vec<String>, flags: BruteforceFlags, completion: ResultSender);
}

#[async_trait]
impl BraveBruteforcer for BruteForcer
{
	async fn HandleBrave(&mut self, vault: Vec<u8>, passwords: Vec<String>, flags: BruteforceFlags, completion: ResultSender)
	{
		match self.BraveUnpackRequest(vault)
		{
			Ok(vault) =>
			{
				let threadpool = self.GetThreadPool();
				let mut clkernels = None;
				let mut devices_info = None;

				let is_gpu_only = flags.contains(BruteforceFlags::GPU_ONLY);
				if is_gpu_only || !flags.contains(BruteforceFlags::CPU_ONLY)
				{
					match self.crackers.get(&ECrackers::PBKDF2_AES_GCM_SIV)
					{
						Some(v) =>
						{
							if let Some(krnls) = v
							{
								if let EGPUDevicesCLKernel::Devices(devices) = &self.gpu_devices
								{
									clkernels = Some(krnls.clone());
									devices_info = Some(devices.clone());
								}
								else if is_gpu_only
								{
									let _ = completion.send(Err("No GPU devices loaded".to_owned()));
									return;
								}
							}
							else if is_gpu_only
							{
								let _ = completion.send(Err("No required kernels loaded. Check previous errors".to_owned()));
								return;
							}
						},
						None =>
						{
							let mut crack = None;
							if let EGPUDevicesCLKernel::Devices(devices) = &self.gpu_devices
							{
								match Self::PK2AGS_LoadKernels(devices)
								{
									Ok(krnls) =>
									{
										let shared = Arc::new(krnls);
										crack = Some(shared.clone());
										clkernels = Some(shared);
										devices_info = Some(devices.clone());
									},
									Err(e) =>
									{
										if is_gpu_only
										{
											let _ = completion.send(Err(e));
											return;
										}

										/*fallback to CPU*/
									}
								}
							}
							else if is_gpu_only
							{
								let _ = completion.send(Err("No GPU devices loaded".to_owned()));
								return;
							}

							self.crackers.insert(ECrackers::PBKDF2_AES_GCM_SIV, crack);
						}
					}
				}

				threadpool.lock().await.spawn(move ||
				{
					let vaultv;
					match Self::BraveVerifyVault(vault)
					{
						Err(e) => { let _ = completion.send(Err(e)); return; },
						Ok(v) => { vaultv = v; }
					}

					//in case of gpu_only this always will be valid, we already tested that
					if let Some(krnls) = clkernels
					{
						//if we got GPU device, then use the GPU device, we have to compile the CL program first tho
						//if we fail to perform it on GPU for whatever god knows why reason, then we fall back to CPU
						let devices_info = devices_info.unwrap();
						match Self::PK2AGS_BruteforceGPU(devices_info, krnls, &vaultv, &passwords)
						{
							Ok(result) =>
							{
								if let Some(result) = result { let _ = completion.send(Ok(Some((vec![result.0.into_bytes()], result.1)))); }
								else { let _ = completion.send(Ok(None)); }
								return;
							},
							Err(e) =>
							{
								if is_gpu_only
								{
									let _ = completion.send(Err(e));
									return;
								}

								/*fallback to CPU*/
							}
						}
					}

					//at this point perform CPU bruteforce
					match Self::PK2AGS_BruteforceCPU(&vaultv, &passwords)
					{
						Ok(result) =>
						{
							if let Some(result) = result { let _ = completion.send(Ok(Some((vec![result.0.into_bytes()], result.1)))); }
							else { let _ = completion.send(Ok(None)); }
						},
						Err(e) => { let _ = completion.send(Err(e)); }	
					}
				});
			},
			Err(e) => { let _ = completion.send(Err(e)); }
		}
	}
}

impl BraveBruteforcerInternal for BruteForcer
{
	fn BraveUnpackRequest(&mut self, vault: Vec<u8>) -> Result<BraveVault, String>
	{
		//the request must be vault data which we gonna parse in here
		let vault = String::from_utf8(vault).map_err(|e| e.to_string())?;
		let vault = serde_json::from_str::<BraveVault>(&vault).map_err(|e| e.to_string())?;
		Ok(vault)
	}

	fn BraveVerifyVault(vault: BraveVault) -> Result<PBKDF2_AES_GCM_SIV_Request, String>
	{
		let vault_data = BASE64_STANDARD.decode(&vault.data).map_err(|e| e.to_string())?;
		let vault_salt = BASE64_STANDARD.decode(&vault.salt).map_err(|e| e.to_string())?;
		let vault_iv = BASE64_STANDARD.decode(&vault.iv).map_err(|e| e.to_string())?;

		//the salt for pbkdf2 must be 16-64 bytes long, iv must be 12-16 bytes long
		//(seems like metamask coders don't realize that any iv for GCM which doesn't match 12 bytes lowers security, who reads the code...)
		if vault_iv.len() != 12 { return Err("Unexpected IV size".to_owned()); }
		if vault_salt.len() < 12 || vault_salt.len() > 32 { return Err("Unexpected salt size".to_owned()); }
		if vault_data.len() <= 16 { return Err("No data to decode".to_owned()); }

		Ok(PBKDF2_AES_GCM_SIV_Request
		{
			data: vault_data,
			iv: vault_iv.try_into().unwrap(),
			salt: vault_salt,
			iterations: vault.iterations,
		})
	}
}