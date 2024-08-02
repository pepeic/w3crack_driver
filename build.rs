fn main()
{
	if cfg!(windows)
	{
		println!(r"cargo:rustc-link-lib=crypto");
	}
}