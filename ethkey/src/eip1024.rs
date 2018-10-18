///EIP 1024
extern crate nacl;
extern crate serde_json;
extern crate base64;

//use nacl;
//use base64;
use rand::{Rng, OsRng};
use super::Error;

const NONCEBYTES: usize = 24;
const PK_25519_BYTES: usize = 32;


fn generate_nonce(nonce:&mut [u8]){
    use std::time::SystemTime;

    let now  = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string();

    let counter = now.as_bytes();
    let l = counter.len();

    assert!(l >= nonce.len());

    nonce[..l].copy_from_slice(&counter);

    let mut r = OsRng::new().unwrap();
    r.fill_bytes(&mut nonce[l..]);
}

#[derive(Serialize)]
pub struct Digest <'a>{
    version: &'a str,
    nonce: &'a[u8],
    ephemPublicKey: &'a str,
    ciphertext: &'a[u8],
}

pub fn getEncryptionPublicKey( privateKey: &[u8]) -> Result< String, Error>{
    let public_key = nacl::public_box::generate_pubkey(privateKey)
                        .unwrap();

    let public_key = public_key.as_slice();

    Ok(base64::encode(public_key))
}



pub fn encrypt(recp_publicKey: &str, msg: &[u8], version: &str, padding: usize, callback: fn(Digest) ) -> Result<String, Error>{

    //generate ephemeral Key pair
    let mut ephemeralSecretKey = [0u8;32];
    let mut r = OsRng::new().unwrap();
    r.fill_bytes(&mut ephemeralSecretKey);

    let ephemeralPublicKey = nacl::public_box::generate_pubkey(&ephemeralSecretKey).unwrap();
    //encode publicKey for transmission
    let ephemeralPublicKey = base64::encode(ephemeralPublicKey.as_slice());

    let mut nonce = [0u8;NONCEBYTES];
    generate_nonce(&mut nonce);


    let recp_publicKey = base64::decode(recp_publicKey).unwrap();

    let cipher = nacl::public_box::pack(msg, &nonce, recp_publicKey.as_ref(), &ephemeralSecretKey)
                    .unwrap();


    let out = Digest{
        version: version,
        nonce: &nonce,
        ephemPublicKey: &ephemeralPublicKey,
        ciphertext: cipher.as_ref(),
    };

    let serialized = serde_json::to_string(&out).unwrap();

    //implementation details left to caller
    //callback(out);

    Ok(serialized)
}



#[derive(Deserialize, Debug)]
pub struct Undigest <'a>{
    version: String,
    nonce: [u8;NONCEBYTES],
    senderPublicKey: &'a str,
    ciphertext: Vec<u8>
}

const VERSION: &str = "x25519-xsalsa20-poly1305";

pub fn decrypt(encrypted_msg: &str, ethSecretKey: &[u8], callback: fn() )-> Result< Vec<u8 >, Error>{
    let deserialized: Undigest = match serde_json::from_str(encrypted_msg){
        Ok(i) => i,
        Err(e) => return Err(Error::Custom("Json unserialize error".to_string()))
    };

    //decode sender public key from base64
    let senderPublicKey = base64::decode(deserialized.senderPublicKey).unwrap();

    if senderPublicKey.len() != PK_25519_BYTES{
        return Err(Error::InvalidPublic);
    }
    if deserialized.nonce.len() < NONCEBYTES{
        return Err(Error::Custom("Invalid Nonce in encryption packet".to_string()));
    }

    if deserialized.version != VERSION.to_string(){
        return Err(Error::Custom("The encryption packet has an invalid version string".to_string()));
    }

    //callback()

    match nacl::public_box::open(&deserialized.ciphertext, &deserialized.nonce,
                                  senderPublicKey.as_ref(), ethSecretKey){
        Ok(i) => Ok(i),
        _ => Err(Error::Custom("Failed to decrypt encryption packet".to_string()))   
    }
}



