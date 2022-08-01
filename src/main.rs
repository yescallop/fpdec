use std::{
    env,
    fs::{self, File},
    io::{prelude::*, BufReader, BufWriter, SeekFrom},
    path::Path,
    str,
};

use anyhow::{bail, ensure, Context, Result};
use des::{
    cipher::{BlockDecrypt, KeyInit},
    Des,
};

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:?}");
    }
}

fn run() -> Result<()> {
    let mut args = env::args();
    args.next().unwrap();
    let in_path = args.next().context("path not provided")?;
    let in_path = Path::new(&in_path);

    let mut in_file = File::open(&in_path).context("failed to open input file")?;
    let len = in_file.metadata()?.len();
    ensure!(len % 8 == 0, "partial block found");

    let name = in_path.file_name().unwrap().to_str().unwrap();
    println!("Input: {}", name);

    let out_path = in_path.with_extension("jpg");

    let mut buf = [0u8; 8];
    in_file.read_exact(&mut buf)?;

    if &buf == b"ENCRYPT:" {
        println!("Encrypted. Searching for key...");
    } else {
        println!("Unencrypted. Copying...");
        fs::copy(in_path, out_path)?;
        return Ok(());
    }

    in_file.read_exact(&mut buf)?;
    let first = buf;

    in_file.seek(SeekFrom::End(-8))?;
    in_file.read_exact(&mut buf)?;
    let last = buf;

    let mut key_buf = [b'0'; 8];
    let (des, pad_len) = loop {
        let des = Des::new((&key_buf).into());
        des.decrypt_block_b2b((&first).into(), (&mut buf).into());
        let header = &buf[..4];

        if header == b"\xFF\xD8\xFF\xE0" || header == b"\xFF\xD8\xFF\xE1" {
            des.decrypt_block_b2b((&last).into(), (&mut buf).into());
            let pad_len = pkcs5_verify(&buf);
            if pad_len > 0 {
                println!("Found key: {}", str::from_utf8(&key_buf).unwrap());
                break (des, pad_len);
            }
        }

        let mut i = 7;
        loop {
            let x = key_buf[i];
            if x != b'F' {
                let t = x & 0b1000;
                key_buf[i] = x + t + ((t >> 2) ^ 0b10);
                break;
            }
            if i == 0 {
                bail!("key not found");
            }
            key_buf[i] = b'0';
            i -= 1;
        }
    };

    in_file.seek(SeekFrom::Start(8))?;
    let mut input = BufReader::new(in_file);

    let out_file = File::create(&out_path).context("failed to create output file")?;
    let mut output = BufWriter::new(out_file);

    loop {
        let read = input.read(&mut buf)?;
        if read == 0 {
            break;
        } else if read != 8 {
            bail!("partial block read");
        }
        des.decrypt_block((&mut buf).into());
        output.write_all(&buf)?;
    }

    let out_file = output.into_inner()?;
    out_file.set_len(len - pad_len - 8)?;

    println!("Decrypted.");

    Ok(())
}

fn pkcs5_verify(block: &[u8; 8]) -> u64 {
    let x = u64::from_be_bytes(*block);
    let pad_len = x & 0xFF;
    if pad_len == 0 || pad_len > 8 {
        return 0;
    }
    let mask = u64::MAX >> ((8 - pad_len) * 8);
    if x & mask != (pad_len * 0x0101010101010101) & mask {
        return 0;
    }
    pad_len
}

// fn to_hex(x: u32) -> u64 {
//     nibbles_to_hex(to_nibbles(x))
// }

// fn to_nibbles(x: u32) -> u64 {
//     use std::arch::x86_64::_pdep_u64;
//     unsafe { _pdep_u64(x as u64, 0x0f0f0f0f0f0f0f0f) }
// }

// macro_rules! packed {
//     ($x:expr) => {
//         ($x as u64) * 0x0101010101010101
//     };
// }

// fn nibbles_to_hex(x: u64) -> u64 {
//     let ascii09 = x + packed!(b'0');
//     let correction = packed!(b'A' - b'0' - 10);

//     let tmp = x + packed!(128 - 10);
//     let msb = tmp & packed!(0x80);
//     let mask = msb - (msb >> 7);

//     ascii09 + (mask & correction)
// }
