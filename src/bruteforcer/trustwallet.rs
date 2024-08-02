use super::*;
use crate::decode_hex;
use async_trait::async_trait;
use opt_pbkdf2_hmac_sha512_scrypt_pbkdf2_hmac_sha256_keccak256::{ OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR, OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Request, OPT_PBKDF2_SPHS256_Cipher, OPT_PBKDF2_SPHS256_Case, SPBKDF2_HMAC_SHA256_Case, SCryptCase };

#[derive(serde::Deserialize)]
struct TrustWalletSCryptCase
{
	salt: String,
	n: u64,
	p: u32,
	r: u32,
}

#[derive(serde::Deserialize)]
struct TrustWalletSPBKDF2_HMAC_SHA256_Case
{
	salt: String,
	iterations: u32,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum TrustWalletPBKDF2_SPHS256_Case
{
	SCrypt(TrustWalletSCryptCase),
	PBKDF2(TrustWalletSPBKDF2_HMAC_SHA256_Case)
}

#[derive(serde::Deserialize)]
enum TrustWalletCipher
{
	#[serde(rename = "aes-128-cbc")]
	AES_CBC_128,

	#[serde(rename = "aes-128-ctr")]
	AES_CTR_128,

	#[serde(rename = "aes-192-ctr")]
	AES_CTR_192,

	#[serde(rename = "aes-256-ctr")]
	AES_CTR_256,
}

#[derive(serde::Deserialize)]
struct TrustWalletVault
{
	data: String,
	iv: String,
	mac: String,
	salts: Vec<String>,
	keylen: u32,
	params: TrustWalletPBKDF2_SPHS256_Case,
	cipher: TrustWalletCipher
}

trait TrustWalletBruteforcerInternal
{
	fn TrustWalletUnpackRequest(&mut self, vault: Vec<u8>) -> Result<TrustWalletVault, String>;
	fn TrustWalletVerifyVault(vault: TrustWalletVault) -> Result<OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Request, String>;
}

#[allow(private_bounds)]
#[async_trait]
pub trait TrustWalletBruteforcer : TrustWalletBruteforcerInternal
{
	async fn HandleTrustWallet(&mut self, vault: Vec<u8>, passwords: Vec<String>, flags: BruteforceFlags, completion: ResultSender);
}

#[async_trait]
impl TrustWalletBruteforcer for BruteForcer
{
	async fn HandleTrustWallet(&mut self, vault: Vec<u8>, passwords: Vec<String>, flags: BruteforceFlags, completion: ResultSender)
	{
		match self.TrustWalletUnpackRequest(vault)
		{
			Ok(vault) =>
			{
				let threadpool = self.GetThreadPool();
				let mut clkernels = None;
				let mut devices_info = None;
				let is_gpu_only = flags.contains(BruteforceFlags::GPU_ONLY);
				if is_gpu_only || !flags.contains(BruteforceFlags::CPU_ONLY)
				{
					match self.crackers.get(&ECrackers::PBKDF2_SHA512_SHA256_SCRYPT_KECCAK256)
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
								match Self::PK2S512SCPK2S256KACC_LoadKernels(devices)
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

							self.crackers.insert(ECrackers::PBKDF2_SHA512_SHA256_SCRYPT_KECCAK256, crack);
						}
					}
				}

				threadpool.lock().await.spawn(move ||
				{
					let vaultv;
					match Self::TrustWalletVerifyVault(vault)
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
						match Self::PK2S512SCPK2S256KACC_BruteforceGPU(devices_info, krnls, &vaultv, &passwords)
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
					match Self::PK2S512SCPK2S256KACC_BruteforceCPU(&vaultv, &passwords)
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

impl TrustWalletBruteforcerInternal for BruteForcer
{
	fn TrustWalletUnpackRequest(&mut self, vault: Vec<u8>) -> Result<TrustWalletVault, String>
	{
		//the request must be vault data which we gonna parse in here
		let vault = String::from_utf8(vault).map_err(|e| e.to_string())?;
		let vault = serde_json::from_str::<TrustWalletVault>(&vault).map_err(|e| e.to_string())?;
		Ok(vault)
	}

	fn TrustWalletVerifyVault(vault: TrustWalletVault) -> Result<OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Request, String>
	{
		let vault_data = decode_hex(&vault.data).map_err(|e| e.to_string())?;
		let vault_iv = decode_hex(&vault.iv).map_err(|e| e.to_string())?;
		let vault_mac = decode_hex(&vault.mac).map_err(|e| e.to_string())?;
		let vault_salts = vault.salts.into_iter().filter_map(|s| if let Ok(v) = decode_hex(&s[2..]) { Some(v) } else { None }).collect::<Vec<_>>();

		let cipher = match vault.cipher
		{
			TrustWalletCipher::AES_CBC_128 => if vault.keylen < 16 { return Err("Unexpected key len".to_owned()); } else { OPT_PBKDF2_SPHS256_Cipher::AES_CTR_128 },
			TrustWalletCipher::AES_CTR_128 => if vault.keylen < 16 { return Err("Unexpected key len".to_owned()); } else { OPT_PBKDF2_SPHS256_Cipher::AES_CTR_128 },
			TrustWalletCipher::AES_CTR_192 => if vault.keylen < 24 { return Err("Unexpected key len".to_owned()); } else { OPT_PBKDF2_SPHS256_Cipher::AES_CTR_192 },
			TrustWalletCipher::AES_CTR_256 => if vault.keylen < 32 { return Err("Unexpected key len".to_owned()); } else { OPT_PBKDF2_SPHS256_Cipher::AES_CTR_256 },
		};
		
		if vault_salts.iter().any(|v| v.len() < 12 || v.len() > 107) { return Err("Unexpected salt size".to_owned()); }
		if vault_iv.len() != 16 { return Err("Unexpected IV size".to_owned()); }
		if vault_mac.len() != 32 { return Err("Unexpected MAC size".to_owned()); }
		if vault_data.len() < 47 { return Err("No data to decode".to_owned()); }

		let kdf = match vault.params
		{
			TrustWalletPBKDF2_SPHS256_Case::SCrypt(data) =>
			{
				if data.n == 0 || (1 << u64::ilog2(data.n)) != data.n { return Err("Invalid SCrypt N param".to_owned()); }

				//for now we always assume R equals to 8, this is required
				//we can change this in the future, however there's no need since trustwallet always uses R = 8
				if data.r != 8 { return Err("Unsupported SCrypt R param".to_owned()); }
				OPT_PBKDF2_SPHS256_Case::SCrypt(SCryptCase
				{
					salt: decode_hex(&data.salt).map_err(|e| e.to_string())?,
					n: data.n,
					p: data.p,
					r: data.r
				})
			},
			TrustWalletPBKDF2_SPHS256_Case::PBKDF2(data) =>
			{
				OPT_PBKDF2_SPHS256_Case::PBKDF2(SPBKDF2_HMAC_SHA256_Case
				{
					salt: decode_hex(&data.salt).map_err(|e| e.to_string())?,
					iterations: data.iterations,
				})
			}
		};

		Ok(OPT_PBKDF2_SHA512_SCrypt_PBKDF2_SHA256_KECCAK256_AES_CTR_Request
		{
			data: vault_data,
			iv: vault_iv,
			mac: vault_mac,
			predev_salts: vault_salts,
			predev_iterations: 20000,
			predev_keylen: 512,
			keylen: vault.keylen,
			kdf, cipher
		})
	}
}