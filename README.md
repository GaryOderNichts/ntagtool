# NTAGTool
A tool for working with Nintendo NFC tags.

### Features
- Encrypt / Decrypt tags
- Verify tag HMAC

Note that NTAGTool uses the [decrypted Wii U NTAG format](https://github.com/devkitPro/wut/blob/c00384924ebfa071214ff40c6ca6e617bdbe30c6/include/ntag/ntag.h#L180-L261) for version 2 tags. Decrypted tags will not match the ones decrypted by 3ds decryption tools.

### Supported tags
- [**Version 0 tags**](https://wiiubrew.org/wiki/Rumble_U_NFC_Figures)  
    These are the tags used by Pokémon Rumble U.
- [**Version 2 tags / amiibo**](https://www.3dbrew.org/wiki/Amiibo)  
    Amiibo are version 2 tags internally.

## Usage
A key file needs to be provided with `--key_file`. The key file is the concatenation of the 3DS unfixed infos and locked secret key dumps.

### Examples
#### Decrypt version 0 tag "dump.bin" to "dump_dec.bin"
```bash
ntagtool decrypt --key_file retail.bin --tag_version 0 dump.bin dump_dec.bin
```
#### Encrypt version 0 tag "dump_dec.bin" to "dump_enc.bin"
```bash
ntagtool encrypt --key_file retail.bin --tag_version 0 dump_dec.bin dump_enc.bin
```
#### Decrypt version 2 tag "amiibo.bin" to "amiibo_dec.bin"
```bash
ntagtool decrypt --key_file retail.bin --tag_version 2 amiibo.bin amiibo_dec.bin
```
#### Encrypt version 2 tag "amiibo_dec.bin" to "amiibo_enc.bin"
```bash
ntagtool encrypt --key_file retail.bin --tag_version 2 amiibo_dec.bin amiibo_enc.bin
```

## Building
#### Requirements
- make
- gcc >= 13
- mbedtls

#### Build executable
```
make
```
