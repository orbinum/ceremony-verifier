//! Any bytes as a ptau: parsed or refused, and every accessor of a parsed one answers or refuses.
#![no_main]

use libfuzzer_sys::fuzz_target;
use orbinum_ceremony_verifier::formats::Ptau;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = Ptau::parse(data) {
        let _ = (p.alpha1(), p.beta1(), p.beta2());
        for domain in [0, 1, 2, 4, 1 << 20, usize::MAX] {
            let _ = p.lagrange_tau_g1(domain);
            let _ = p.lagrange_tau_g2(domain);
            let _ = p.lagrange_alpha_tau_g1(domain);
            let _ = p.lagrange_beta_tau_g1(domain);
        }
        for i in [0, 1, usize::MAX] {
            let _ = p.tau_g1_at(i);
        }
    }
});
