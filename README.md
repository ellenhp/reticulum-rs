# reticulum-rs

WIP rewrite of Reticulum in Rust explicitly targeted at the ESP32 (no tokio, avoids memory-inefficient data structures. etc). Not ready for use. Rule of thumb with stuff like this: If you wouldn't send a POST request with your cleartext to `nsa.gov` then it probably doesn't belong in this software.

## Roadmap

Anything with a checkmark here is both implemented and tested.

- [x] Cryptographic primitives
- [x] Wire format (de)serialization
- [x] Announce packet generation
- [x] Event loop boilerplate
- [ ] Path responses
- [ ] Maintain a routing table
- [ ] Link establishment
- [ ] Test a basic channel end to end
- [ ] Overhaul virtual network system to test disrupted networks.
- [ ] Forward messages if appropriate
- [ ] Test a DTN channel end to end
- [ ] Groups
- [ ] Cleartext messages
- [ ] Other stuff? There are a lot of message types and they probably all do something.
- [ ] Integration tests

## Licensing

Dual license under Apache 2.0 and MIT.