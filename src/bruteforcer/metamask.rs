use super::*;
use base64::{ Engine as _, prelude::* };
use async_trait::async_trait;
use pbkdf2_hmac_sha256_aes_gcm::{ PBKDF2_AES_GCM, PBKDF2_AES_GCM_Request };
use unescape::unescape;

#[derive(serde::Deserialize)]
pub struct PBKDF2Params
{
	pub iterations: Option<u32>
}

#[derive(serde::Deserialize)]
pub struct KeyMetadata
{
	pub algorithm: Option<String>,

	//we only support pbkdf2 for now (well, as well as metamask only supports pbkdf2 at the moment)
	pub params: Option<PBKDF2Params>
}

#[derive(serde::Deserialize)]
pub struct MetamaskVault
{
	pub data: String,
	pub iv: String,
	pub salt: String,

	#[serde(rename = "keyMetadata")]
	pub key_metadata: Option<KeyMetadata>
}

#[derive(serde::Deserialize)]
struct MetamaskVaultDataDecrypted
{
	mnemonic: Option<Vec<u8>>,

	#[serde(rename = "hdPath")]
	dpath: Option<String>,

	#[serde(rename = "numberOfAccounts")]
	accs: Option<u32>
}

#[derive(serde::Deserialize)]
struct MetamaskVaultDecrypted
{
	data: MetamaskVaultDataDecrypted
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct RoninVaultDecrypted
{
	mnemonic: String,

	#[serde(rename = "totalAccount")]
	accs: u32
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BinanceAddresses
{
	#[serde(rename = "type")]
	addrtype: String,

	#[serde(rename = "privateKey")]
	private_key: String,
	
	address: String,
}

#[derive(serde::Deserialize)]
struct BinanceAccounts
{
	mnemonic: String,
	addresses: Vec<BinanceAddresses>
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct BinanceVaultDecrypted
{
	version: String,
	accounts: Vec<BinanceAccounts>
}

#[derive(serde::Serialize)]
struct BinanceVaultRepacked
{
	mnemonic: String,
	addresses: Vec<BinanceAddresses>
}

trait MetaMaskBruteforcer
{
	fn MMUnpackRequest(&mut self, vault: Vec<u8>) -> Result<MetamaskVault, String>;
	fn MMVerifyVault(vault: MetamaskVault) -> Result<PBKDF2_AES_GCM_Request, String>;
	fn ExtractWallet(vault_decrypted: String, wtype: WalletType, preparse: bool) -> Vec<Vec<u8>>;
	fn MMExtractWallet(vault_decrypted: String) -> Vec<Vec<u8>>;
	fn RoninExtractWallet(vault_decrypted: String) -> Vec<Vec<u8>>;
	fn BinanceExtractWallet(vault_decrypted: String) -> Vec<Vec<u8>>;
}

#[allow(private_bounds)]
#[async_trait]
pub trait MMBruteforcer : MetaMaskBruteforcer
{
	async fn HandleMetamask(&mut self, vault: Vec<u8>, passwords: Vec<String>, wtype: WalletType, flags: BruteforceFlags, completion: ResultSender);
}

#[async_trait]
impl MMBruteforcer for BruteForcer
{
	async fn HandleMetamask(&mut self, vault: Vec<u8>, passwords: Vec<String>, wtype: WalletType, flags: BruteforceFlags, completion: ResultSender)
	{
		match self.MMUnpackRequest(vault)
		{
			Ok(vault) =>
			{
				let threadpool = self.GetThreadPool();
				let mut clkernels = None;
				let mut devices_info = None;
				let is_gpu_only = flags.contains(BruteforceFlags::GPU_ONLY);
				if is_gpu_only || !flags.contains(BruteforceFlags::CPU_ONLY)
				{
					match self.crackers.get(&ECrackers::PBKDF2_AES_GCM)
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
								match Self::PK2AG_LoadKernels(devices)
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

							self.crackers.insert(ECrackers::PBKDF2_AES_GCM, crack);
						}
					}
				}

				threadpool.lock().await.spawn(move ||
				{
					let vaultv;
					match Self::MMVerifyVault(vault)
					{
						Err(e) => { let _ = completion.send(Err(e)); return; },
						Ok(v) => { vaultv = v; }
					}

					let preparse = flags.contains(BruteforceFlags::PREPARSE);

					//in case of gpu_only this always will be valid, we already tested that
					if let Some(krnls) = clkernels
					{
						//if we got GPU device, then use the GPU device, we have to compile the CL program first tho
						//if we fail to perform it on GPU for whatever god knows why reason, then we fall back to CPU
						let devices_info = devices_info.unwrap();
						match Self::PK2AG_BruteforceGPU(devices_info, krnls, &vaultv, &passwords)
						{
							Ok(result) =>
							{
								if let Some(result) = result { let _ = completion.send(Ok(Some((Self::ExtractWallet(result.0, wtype, preparse), result.1)))); }
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
					match Self::PK2AG_BruteforceCPU(&vaultv, &passwords)
					{
						Ok(result) =>
						{
							if let Some(result) = result { let _ = completion.send(Ok(Some((Self::ExtractWallet(result.0, wtype, preparse), result.1)))); }
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

impl MetaMaskBruteforcer for BruteForcer
{
	fn MMUnpackRequest(&mut self, vault: Vec<u8>) -> Result<MetamaskVault, String>
	{
		//the request must be vault data which we gonna parse in here
		let vault = String::from_utf8(vault).map_err(|e| e.to_string())?;
		let vault = serde_json::from_str::<MetamaskVault>(&vault).map_err(|e| e.to_string())?;
		Ok(vault)
	}

	fn MMVerifyVault(vault: MetamaskVault) -> Result<PBKDF2_AES_GCM_Request, String>
	{
		//if there's no keyMetadata, assume pbkdf2 and 10000 iterations (default)
		//if there is, then use data from there
		let mut iterations = 10000u32;
		if let Some(metadata) = &vault.key_metadata
		{
			if let Some(alg) = &metadata.algorithm
			{
				//the algorithm always must be valid, if it is not, then issue must be created at github page
				//metamask only supports pbkdf2 at the moment, however this may be changed in the future
				if alg.to_lowercase().as_str().cmp("pbkdf2") != std::cmp::Ordering::Equal
				{ return Err("Unsupported algorithm. Only pbkdf2 is supported at the moment".to_owned()); }
			}

			if let Some(params) = &metadata.params
			{ iterations = params.iterations.unwrap_or(10000u32); }
		}

		let vault_data = BASE64_STANDARD.decode(&vault.data).map_err(|e| e.to_string())?;
		let vault_salt = BASE64_STANDARD.decode(&vault.salt).map_err(|e| e.to_string())?;
		let vault_iv = BASE64_STANDARD.decode(&vault.iv).map_err(|e| e.to_string())?;

		//the salt for pbkdf2 must be 16-64 bytes long, iv must be 12-16 bytes long
		//(seems like metamask coders don't realize that any iv for GCM which doesn't match 12 bytes lowers security, who reads the code...)
		if vault_iv.len() < 12 || vault_iv.len() > 16 { return Err("Unexpected IV size".to_owned()); }
		if vault_salt.len() < 12 || vault_salt.len() > 32 { return Err("Unexpected salt size".to_owned()); }
		if vault_data.len() <= 16 { return Err("No data to decode".to_owned()); }

		Ok(PBKDF2_AES_GCM_Request
		{
			data: vault_data,
			iv: vault_iv,
			salt: vault_salt,
			iterations,
		})
	}

	fn ExtractWallet(vault_decrypted: String, wtype: WalletType, preparse: bool) -> Vec<Vec<u8>>
	{
		if preparse
		{
			match wtype
			{
				WalletType::MetaMask => Self::MMExtractWallet(vault_decrypted),
				WalletType::Ronin => Self::RoninExtractWallet(vault_decrypted),
				WalletType::Binance => Self::BinanceExtractWallet(vault_decrypted),
				_ => vec![]
			}
		}
		else
		{
			//at this point simply return "as is"
			vec![vault_decrypted.into_bytes()]
		}
	}

	fn MMExtractWallet(vault_decrypted: String) -> Vec<Vec<u8>>
	{
		if let Ok(result) = serde_json::from_str::<Vec<MetamaskVaultDecrypted>>(&vault_decrypted)
		{
			result.into_iter().filter_map(|v|
			{
				let v = v.data;

				//check if we got any accounts and derivation path here, if we didn't, then this is likely useless entry
				if v.accs.is_some() && v.dpath.is_some() && v.mnemonic.is_some() { Some(v.mnemonic.unwrap()) }
				else { None }
			}).collect::<Vec<_>>()
		}
		else { vec![vault_decrypted.into_bytes()] }
	}

	fn RoninExtractWallet(vault_decrypted: String) -> Vec<Vec<u8>>
	{
		let Some(mut vault) = unescape(&vault_decrypted) else { return vec![vault_decrypted.into_bytes()]; };
		
		//remove the quotes
		vault = vault.split_off(1);
		vault.truncate(vault.len() - 1);
		if let Ok(result) = serde_json::from_str::<RoninVaultDecrypted>(&vault)
		{ vec![result.mnemonic.into_bytes()] }
		else { vec![vault_decrypted.into_bytes()] }
	}

	fn BinanceExtractWallet(vault_decrypted: String) -> Vec<Vec<u8>>
	{
		//remove the quotes
		if let Ok(result) = serde_json::from_str::<BinanceVaultDecrypted>(&vault_decrypted)
		{
			result.accounts.into_iter().map(|acc|
			{
				let repacked = BinanceVaultRepacked
				{
					mnemonic: acc.mnemonic,
					addresses: acc.addresses,
				};
				let res = serde_json::to_string(&repacked).unwrap();
				res.into_bytes()
			}).collect::<Vec<_>>()
		}
		else { vec![vault_decrypted.into_bytes()] }
	}
}