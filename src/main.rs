//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use aes::{
	cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
	Aes128,
};
use rand::prelude::*;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
	todo!("Maybe this should be a library crate. TBD");
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.encrypt_block(&mut block);

	block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.decrypt_block(&mut block);

	block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
	// When twe have a multiple the second term is 0
	let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

	for _ in 0..number_pad_bytes {
		data.push(number_pad_bytes as u8);
	}

	data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
	let mut blocks = Vec::new();
	let mut i = 0;
	while i < data.len() {
		let mut block: [u8; BLOCK_SIZE] = Default::default();
		block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
		blocks.push(block);

		i += BLOCK_SIZE;
	}

	blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
	let mut data = Vec::with_capacity(blocks.len() * BLOCK_SIZE);
    for block in blocks {
        data.extend_from_slice(&block);
    }
    data
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {
	if data.is_empty() {
        return data;
    }

    let data_len = data.len();
    let pad_byte = data[data_len - 1] as usize;

    if pad_byte <= data_len
        && data[data_len - pad_byte..]
            .iter()
            .all(|&byte| byte as usize == pad_byte)
    {
        return data[0..data_len - pad_byte].to_vec();
    }

    data
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
	let blocks = match plain_text.len() % BLOCK_SIZE {
        0 => group(plain_text),
        _ => group(pad(plain_text))
    };

    let mut encrypted_blocks: Vec<[u8; BLOCK_SIZE]> = vec![];
    for b in blocks {
        encrypted_blocks.push(aes_encrypt(b, &key));
    }

    let mut ciphertext = Vec::with_capacity(encrypted_blocks.len() * BLOCK_SIZE);
    for b in encrypted_blocks {
        ciphertext.extend_from_slice(&b);
    }

    ciphertext
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	let blocks = group(cipher_text);

    let mut decrypted_blocks: Vec<[u8; BLOCK_SIZE]> = vec![];
    for b in blocks {
        decrypted_blocks.push(aes_decrypt(b, &key))
    }

    let decrypted_data = un_group(decrypted_blocks);
    un_pad(decrypted_data)
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Remember to generate a random initialization vector for the first block.
	let random_iv: [u8; BLOCK_SIZE] = rand::random();
	let blocks = match plain_text.len() % BLOCK_SIZE {
        0 => group(plain_text),
        _ => group(pad(plain_text))
    };
	let mut encrypted_blocks: Vec<[u8; BLOCK_SIZE]> = vec![];
	let mut prev_block_cipher = random_iv.clone();
	for block in blocks{

		let interim_vec: Vec<u8> = block
						.iter()
						.zip(prev_block_cipher.iter())
						.map(|(&x1, &x2)| x1 ^ x2)
						.collect();
		let mut input: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
		input.copy_from_slice(&interim_vec);
		
		prev_block_cipher = aes_encrypt(input, &key);
		encrypted_blocks.push(prev_block_cipher);
	}

	let mut ciphertext = Vec::with_capacity(encrypted_blocks.len() * BLOCK_SIZE + 1);
	ciphertext.extend_from_slice(&random_iv);
    for b in encrypted_blocks {
        ciphertext.extend_from_slice(&b);
    }

    ciphertext
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	let mut blocks = group(cipher_text).into_iter();

    let mut decrypted_blocks: Vec<[u8; BLOCK_SIZE]> = vec![];
	// add test for empty case
	let mut prev_block_cipher: [u8; BLOCK_SIZE] = blocks.next().unwrap();
    for block in blocks{
		let curr_block = aes_decrypt(block, &key);
		let interim_vec: Vec<u8> = curr_block
							.iter()
							.zip(prev_block_cipher.iter())
							.map(|(&x1, &x2)| x1 ^ x2)
							.collect();
		prev_block_cipher = block.clone();

		let mut input: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
		input.copy_from_slice(&interim_vec);


        decrypted_blocks.push(input);
    }

    let decrypted_data = un_group(decrypted_blocks);
    un_pad(decrypted_data)
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Remember to generate a random nonce
	todo!()
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	todo!()
}