#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
#![allow(dead_code)]
#![feature(raw_ref_op)]
#![feature(layout_for_ptr)]

use pyo3::{ prelude::*, types::{ PyBytes, PyList, PySet, PyTuple }, exceptions::{ PyValueError, PyIOError } };
use tokio::sync::{ oneshot, RwLock, Mutex };
use tokio_util::{ task::TaskTracker, sync::CancellationToken };
use std::{ ptr::{ addr_of, addr_of_mut }, sync::{atomic::{ AtomicUsize, Ordering }, Arc} };
use once_cell::sync::{ Lazy, OnceCell };

bitflags::bitflags!
{
	#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
	pub struct BruteforceFlags : u32
	{
		const NONE = 0;
		const PREPARSE = 1 << 0;
		const CPU_ONLY = 1 << 1;
		const GPU_ONLY = 1 << 2;
	}
}

#[pyclass]
#[repr(usize)]
#[derive(Clone, Copy)]
pub enum WalletType
{
	MetaMask,
	Brave,
	Ronin,
	Binance,
	TrustWallet,
}

pub type CrackRes = (Vec<Vec<u8>>, String);

#[derive(Debug)]
enum CrackResult
{
	Ok(Option<CrackRes>), //returns: None if password not found. Vec<results> | String with password which matches
	Err(String),
}

pub struct CancelControl
{
	pub stop_token: CancellationToken,
	pub tracker: TaskTracker,
	contexts: AtomicUsize
}

mod bruteforcer;
mod utils;

pub use utils::*;
use bruteforcer::{ BruteForcer, Task };

#[pyclass]
struct WalletCrackContext
{
	control: Arc<CancelControl>
}

#[pyclass]
pub struct WalletCrackConfig
{
	#[pyo3(get, set)]
	preparse: bool,

	#[pyo3(get, set)]
	cpu_only: bool,

	#[pyo3(get, set)]
	gpu_only: bool,
}

#[pymethods]
impl WalletCrackConfig
{
	#[new]
	pub fn new(preparse: Option<bool>,
		cpu_only: Option<bool>,
		gpu_only: Option<bool>) -> Self
	{
		let preparse = preparse.unwrap_or(false);
		let cpu_only = cpu_only.unwrap_or(false);
		let gpu_only = gpu_only.unwrap_or(false);
		Self { preparse, cpu_only, gpu_only }
	}
}

#[pymethods]
impl WalletCrackContext
{
	#[new]
	pub fn new() -> PyResult<Self>
	{
		match ModuleInternal::InstanceMut().Initialize()
		{
			Ok(control) => Ok(Self{ control }),
			Err(e) => Err(PyValueError::new_err(e))
		}
	}

	pub fn try_crack_wallet<'a>(&self, py: Python<'a>, wtype: WalletType, wallet_data: &PyBytes, passwords: &PySet, cfg: &WalletCrackConfig) -> PyResult<&'a PyAny>
	{
		let wdata: Vec<u8> = wallet_data.as_bytes().to_vec();
		let passwords = passwords.iter().filter_map(|v| if let Ok(s) = String::extract(v) { Some(s) } else { None }).collect::<Vec<_>>();
		let mut flags = BruteforceFlags::NONE;
		if cfg.preparse { flags |= BruteforceFlags::PREPARSE; }
		if cfg.cpu_only { flags |= BruteforceFlags::CPU_ONLY; }
		if cfg.gpu_only { flags |= BruteforceFlags::GPU_ONLY; }

		pyo3_asyncio::tokio::future_into_py(py, async move
		{
			//we need to do that in the future since the function is async and will be awaited on python side
			let exclusive_test_1 = BruteforceFlags::CPU_ONLY | BruteforceFlags::GPU_ONLY;
			if ((flags & exclusive_test_1) ^ exclusive_test_1) == BruteforceFlags::NONE
			{
				let result = "CPU and GPU only flags are exclusive".to_owned();
				return Python::with_gil(|py| Ok(result.into_py(py)));
			}

			let (snd, rcv) = oneshot::channel();
			let result =
			match BruteForcer::Instance().Queue(Task{ wtype, wdata, passwords, flags }, snd)
			{
				Err(e) => { CrackResult::Err(e) },
				Ok(_) =>
				{
					match rcv.await
					{
						Ok(res) =>
						{
							match res
							{
								Ok(res) => { CrackResult::Ok(res) },
								Err(e) => { CrackResult::Err(e) }
							}
						},
						Err(e) => { CrackResult::Err(e.to_string()) }
					}
				}
			};

			Python::with_gil(|py| Ok(result.into_py(py)))
		})
	}
}

impl Drop for WalletCrackContext
{
	fn drop(&mut self)
	{
		let _ = self.control.contexts.fetch_sub(1, Ordering::SeqCst);
	}
}

#[pymodule]
fn wcrack(_py: Python<'_>, m: &PyModule) -> PyResult<()>
{
	m.add_function(wrap_pyfunction!(try_shutdown, m)?)?;
	m.add_class::<WalletType>()?;
	m.add_class::<WalletCrackContext>()?;
	m.add_class::<WalletCrackConfig>()?;
	Ok(())
}

impl IntoPy<PyObject> for CrackResult
{
	fn into_py(self, py: Python<'_>) -> PyObject
	{
		match self
		{
			Self::Ok(val) => if let Some((r, p)) = val
			{ PyTuple::new(py, vec![PyList::new(py, r.into_iter().map(|v| PyBytes::new(py, &v).into()).collect::<Vec<PyObject>>()).into(), p.into_py(py)]).into() }
			else { py.None() },
			Self::Err(val) => val.into_py(py),
		}
	}
}

pub struct ModuleInternal
{
	cancel_control: RwLock<Option<Arc<CancelControl>>>,
	init_control: Mutex<()>
}

impl ModuleInternal
{
	#[inline] pub fn Instance() -> &'static Self { unsafe { addr_of!(g_Module).as_ref().unwrap_unchecked() } }
	#[inline] fn InstanceMut() -> &'static mut Self { unsafe { addr_of_mut!(g_Module).as_mut().unwrap_unchecked() } }

	pub fn GetCC(&self) -> Option<Arc<CancelControl>> { if let Some(cc) = self.cancel_control.blocking_read().as_ref() { Some(cc.clone()) } else { None } }
	pub async fn GetCCAsync(&self) -> Option<Arc<CancelControl>> { if let Some(cc) = self.cancel_control.read().await.as_ref() { Some(cc.clone()) } else { None } }

	async fn AsyncMain(&self, notify: oneshot::Sender<()>, control: Arc<CancelControl>)
	{
		{
			let _lock = self.init_control.lock().await;
			BruteForcer::InstanceMut().InitializeAndRun().await;
			let _ = notify.send(());
		}

		//this is our main future, we have to block here
		//however how do we know for how long to block?
		//Well, assume we need to block until the stop is requested
		control.stop_token.cancelled().await;

		//wait until all the tasks are complete (they should listen to the stop token tho)
		control.tracker.close();
		control.tracker.wait().await;
	}

	//only context new function MUST call this function
	fn Initialize(&'static mut self) -> Result<Arc<CancelControl>, String>
	{
		//lock this one exclusively to avoid race conditions
		//we init everything here only once
		let mut control_lock = self.cancel_control.blocking_write();
		if let Some(control) = control_lock.as_ref()
		{
			let control = control.clone();
			let _ = control.contexts.fetch_add(1, Ordering::Relaxed);
			return Ok(control);
		}

		//create new stop token and tracker
		let tracker = TaskTracker::new();
		let stop_token = CancellationToken::new();
		let cancel_control = Arc::new(CancelControl{ stop_token, tracker, contexts: AtomicUsize::new(1) });
		*control_lock = Some(cancel_control.clone());
		std::mem::drop(control_lock);

		let (snd, rcv) = oneshot::channel();
		let moved_cancel_control = cancel_control.clone();
		let runtime = g_TokioRuntime.get_or_init(||
		{
			tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.thread_name("internal")
				.build()
				.unwrap()
		});
		
		let _ = pyo3_asyncio::tokio::init_with_runtime(runtime);
		let _ = std::thread::spawn(move ||
		{
			runtime.block_on(self.AsyncMain(snd, moved_cancel_control));
			let _lock = self.init_control.blocking_lock();
			BruteForcer::InstanceMut().Deinit();
		});

		//wait for initialization
		rcv.blocking_recv().map_err(|e| e.to_string())?;
		Ok(cancel_control)
	}

	fn SignalExit(&self, force: bool) -> Result<(), &str>
	{
		if let Some(control) = self.cancel_control.blocking_write().as_ref()
		{
			if !force
			{
				if control.contexts.load(Ordering::Acquire) == 0 { control.stop_token.cancel(); }
				else { return Err("There are still contexts running"); }
			}
			else { control.stop_token.cancel(); }
		}

		Ok(())
	}
}

#[pyfunction]
fn try_shutdown(_py: Python<'_>, force: bool) -> PyResult<()>
{
	let _ = ModuleInternal::Instance().SignalExit(force).map_err(|e| PyIOError::new_err(e))?;
	Ok(())
}

static mut g_Module: Lazy<ModuleInternal> = Lazy::new(||
{
	let instance = ModuleInternal
	{
		cancel_control: RwLock::new(None),
		init_control: Mutex::new(())
	};
	instance
});

static g_TokioRuntime: OnceCell<tokio::runtime::Runtime> = OnceCell::new();