// CP0 language probe: identical naive literal-byte search to probe.go.
// This is NOT the RNC detection engine, a credential rule, or a production benchmark.
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: probe file");
        process::exit(64);
    }
    let data = match fs::read(&args[1]) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    };
    let needle = b"RNC_SYNTH_KEY_";
    let mut count = 0_usize;
    for i in 0..=data.len().saturating_sub(needle.len()) {
        if data.len() >= needle.len() && &data[i..i + needle.len()] == needle {
            count += 1;
        }
    }
    println!("{count}");
}
