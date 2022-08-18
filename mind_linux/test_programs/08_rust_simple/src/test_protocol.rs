use libc;
// use std::io;
// use std::ptr;

fn main() {
    println!("Start mmap test");
    unsafe {
        let addr = libc::mmap(0 as *mut libc::c_void, 1024*1024*1024*8, 0x1 | 0x2, 0xfe, -1, 0);
        if addr == libc::MAP_FAILED {
            println!("mmap error!");
            return ;
        }
    }
    println!("End mmap test");
}
