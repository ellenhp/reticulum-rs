# reticulum-rs

Partial rewrite of Reticulum in Rust for `no_std` targets. Not ready for use. Work has stopped on this project in favor of the [Liminality](https://github.com/ellenhp/liminality) reference implementation, which provides trustworthy and comprehensible security properties by using the noise protocol framework, and strong (but not very comprehensible) privacy properties. This project is probably a good starting point if someone else wants to continue work in this space, but it's not polished and probably has bugs.

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
