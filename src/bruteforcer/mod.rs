#![allow(invalid_value)]

use crate::{ BruteforceFlags, CancelControl, CrackRes, ModuleInternal, WalletType };
use once_cell::sync::Lazy;
use tokio::sync::{ Mutex, oneshot::Sender, mpsc };
use std::{ collections::HashMap, hash::Hash, ptr::{ addr_of, addr_of_mut }, sync::{ Arc, Mutex as ThrdMutex } };
use opencl3::platform::get_platforms;
use opencl3::device::Device as GPUDevice;
use opencl3::context::Context;
use opencl3::program::Program;
use opencl3::kernel::Kernel;
use cl3::device::{ CL_DEVICE_TYPE_GPU, CL_DEVICE_SVM_COARSE_GRAIN_BUFFER, CL_DEVICE_SVM_FINE_GRAIN_BUFFER };

pub struct Task
{
	pub wtype: WalletType,
	pub wdata: Vec<u8>,
	pub passwords: Vec<String>,
	pub flags: BruteforceFlags,
}

pub type ResultSender = Sender<Result<Option<CrackRes>, String>>;
type TaskWithSender = (Task, ResultSender);

struct OpenCLProgram
{
	ctx: Context,
	pgs: Vec<Program>,
	krnls: HashMap<&'static str, WrappedKernel>
}

//wallets we support bruteforcing for
mod metamask;
mod brave;
mod trustwallet;

//bruteforce algorithms used
pub mod algs;
mod pbkdf2_hmac_sha256_aes_gcm;
mod pbkdf2_hmac_sha256_aes_gcm_siv;
mod opt_pbkdf2_hmac_sha512_scrypt_pbkdf2_hmac_sha256_keccak256;

use metamask::MMBruteforcer;
use brave::BraveBruteforcer;
use trustwallet::TrustWalletBruteforcer;

#[repr(usize)]
#[derive(Eq, PartialEq, Hash, Clone, Copy)]
pub enum ECrackers
{
	PBKDF2_AES_GCM,
	PBKDF2_AES_GCM_SIV,
	PBKDF2_SHA512_SHA256_SCRYPT_KECCAK256,
}

pub struct WrappedKernel
{
	krnl: Kernel,
	mgws: usize,
	mtx: ThrdMutex<()>
}

enum EGPUDevicesCLKernel
{
	Uninited,
	None,
	Devices(Arc<Vec<GPUDeviceInfo>>)
}

struct GPUDeviceInfo
{
	device: GPUDevice,

	//these are cached so we don't make extra requests to opencl api
	max_memory_alloc: u64,
	max_single_argument_size: u64,
}

pub struct BruteForcer
{
	//these are initialized at the start
	queue: Option<mpsc::UnboundedSender<TaskWithSender>>,
	gpu_devices: EGPUDevicesCLKernel,

	//these are initialized on demand
	cpu_threadpool: Option<Arc<Mutex<rayon::ThreadPool>>>,
	crackers: HashMap<ECrackers, Option<Arc<OpenCLProgram>>>
}

impl BruteForcer
{
	#[inline] pub fn Instance() -> &'static Self { unsafe { addr_of!(g_Singleton).as_ref().unwrap_unchecked() } }
	#[inline] pub fn InstanceMut() -> &'static mut Self { unsafe { addr_of_mut!(g_Singleton).as_mut().unwrap_unchecked() } }

	pub async fn InitializeAndRun(&'static mut self)
	{
		//now check if we got opencl installed, if we do, then check if we got GPU here
		//if we don't, then we got another implementations which will be faster than opencl CPU ones
		let Some(cc) = ModuleInternal::Instance().GetCCAsync().await else { return; };

		if let EGPUDevicesCLKernel::Uninited = self.gpu_devices
		{
			if let Ok(platforms) = get_platforms()
			{
				let opencl2 = "OpenCL 2";
				let opencl3 = "OpenCL 3";

				//find an OpenCL fine grained shared virtual memory, platform and device
				let mut gpudevices = Vec::<GPUDeviceInfo>::new();
				for p in platforms
				{
					if let Ok(platform_version) = p.version()
					{
						if platform_version.contains(&opencl2) || platform_version.contains(&opencl3)
						{
							if let Ok(devices) = p.get_devices(CL_DEVICE_TYPE_GPU)
							{
								for dev_id in devices
								{
									let device = GPUDevice::new(dev_id);
									let svm_mem_capability = device.svm_mem_capability();
									if (svm_mem_capability & (CL_DEVICE_SVM_FINE_GRAIN_BUFFER | CL_DEVICE_SVM_COARSE_GRAIN_BUFFER)) != 0
									{
										unsafe
										{
											let mut device_info: GPUDeviceInfo = std::mem::MaybeUninit::uninit().assume_init();
											device_info.max_memory_alloc = device.max_mem_alloc_size().unwrap_or(0) as u64;
											device_info.max_single_argument_size = device.max_parameter_size().unwrap_or(0) as u64;
											addr_of_mut!(device_info.device).write(device);
											gpudevices.push(device_info);
										}
									}
								}
							}
						}
					}
				}

				if gpudevices.len() != 0 { self.gpu_devices = EGPUDevicesCLKernel::Devices(Arc::new(gpudevices)); }
				else { self.gpu_devices = EGPUDevicesCLKernel::None; }
			}
		}
		

		let (snd, rcv) = mpsc::unbounded_channel();
		self.queue = Some(snd);
		let _ = cc.clone().tracker.spawn(async move { self.Run(rcv, cc).await; });
	}

	pub fn Deinit(&mut self)
	{
		//cpu threadpool must be destroyed now, as well as other resources
		let _ = self.cpu_threadpool.take();
		self.crackers.clear();
		self.gpu_devices = EGPUDevicesCLKernel::Uninited;
	}

	async fn Run(&'static mut self, mut rcv: mpsc::UnboundedReceiver<TaskWithSender>, cancel_control: Arc<CancelControl>)
	{
		'mainloop: loop
		{
			tokio::select!
			{
				req = rcv.recv() =>
				{
					match req
					{
						Some(data) =>
						{
							let (task, completion) = data;

							#[allow(unreachable_patterns)]
							match task.wtype
							{
								//these are metamask-like wallets, we handle them all together
								WalletType::MetaMask | WalletType::Ronin | WalletType::Binance =>
								{ self.HandleMetamask(task.wdata, task.passwords, task.wtype, task.flags, completion).await; },
								WalletType::Brave => { self.HandleBrave(task.wdata, task.passwords, task.flags, completion).await; },
								WalletType::TrustWallet => { self.HandleTrustWallet(task.wdata, task.passwords, task.flags, completion).await; },
								_ => { /* just ignore this request*/ }
							}
						},
						None => { break 'mainloop; }
					}
				},
				() = cancel_control.stop_token.cancelled() => { break 'mainloop; }
			}
		}
	}

	fn GetThreadPool(&mut self) -> Arc<Mutex<rayon::ThreadPool>>
	{
		if self.cpu_threadpool.is_none()
		{
			//okay at this point we need to determine what opencl version we got here
			//and if none, then select CPU-based bruteforce functions
			//there's no reason to bruteforce on more threads than available hardware concurrency
			let cpu_concurrency = std::thread::available_parallelism().map(|v| v.get()).unwrap_or(1);
			self.cpu_threadpool = Some(Arc::new(Mutex::new(rayon::ThreadPoolBuilder::new().num_threads(cpu_concurrency).build().unwrap())));
		}

		self.cpu_threadpool.as_ref().unwrap().clone()
	}

	pub fn Queue(&self, task: Task, channel: ResultSender) -> Result<(), String>
	{
		unsafe { self.queue.as_ref().unwrap_unchecked() }.send((task, channel)).map_err(|e| e.to_string())?;
		Ok(())
	}
}

static mut g_Singleton: Lazy<BruteForcer> = Lazy::new(||
{
	let instance = BruteForcer
	{
		queue: None,
		gpu_devices: EGPUDevicesCLKernel::Uninited,
		cpu_threadpool: None,
		crackers: HashMap::new()
	};
	instance
});

//for whatever reason opencl crate doesn't implement Sync for the Kernel
unsafe impl Send for WrappedKernel {}
unsafe impl Sync for WrappedKernel {}

impl Clone for WrappedKernel
{
	fn clone(&self) -> Self
	{
		let krnl = self.krnl.clone();
		Self{ krnl, mgws: self.mgws, mtx: ThrdMutex::new(()) }
	}
}