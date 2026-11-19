// kmip's client against a live key manager (PyKMIP in Docker, or
// goose-kmipd): test/scenario.goose's checks over TLS, with a client
// certificate. scripts/interop.py runs it in each version.
//
//   goose interop_client.goose -- HOST PORT CERTS VERSION RUN
//
// CERTS holds ca.pem, client.pem and client.key (the server's certificate
// is for kmip.example.com); VERSION is 1.0 ... 2.0 or auto. A line per
// check, then the counts; exit 1 on any failure.

import std;
import kmip from "..";
import entropy from "SorinS/entropygoose@v0.7.0";
import net from "SorinS/netgoose@v0.7.0";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import xml from "SorinS/xmlgoose@v0.7.0";
import tls from "SorinS/tlsgoose@v0.7.0";
import ntlm from "SorinS/ntlmgoose@v0.7.0";
import http from "SorinS/httpgoose@v0.7.0";
import kmip.client;
import tls.handshake;
import scenario;

fn pem_der(path: const u8[:], label: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    var out: u8[>..] = [];
    if !read_file(path, text) { return out; }
    let ders, ok = asn1::pem_decode(text, label);
    for d in ders { out.append(d); }
    return out;
}

fn main() {
    let a = args();
    guard a.len >= 6 else { print("usage: interop_client HOST PORT CERTS VERSION RUN"); exit(2); }
    let port, pok = parse_int(a[2], 10);
    let dir = a[3];
    scenario::verbose = true;
    var cc = kmip::tls_config("kmip.example.com", pem_der(str(dir, "/ca.pem"), "CERTIFICATE"));
    let certok = tls::set_client_certificate(cc, pem_der(str(dir, "/client.pem"), "CERTIFICATE"),
                                             pem_der(str(dir, "/client.key"), "PRIVATE KEY"));
    scenario::check("client certificate", certok);
    var c, e = kmip::dial(a[1], port, cc);
    if scenario::check_e(c, "dial", e) {
        scenario::run(c, a[4], a[5]);
        kmip::close(c);
    }
    print(scenario::checks, " checks, ", scenario::failures, " failures");
    if scenario::failures > 0 { exit(1); }
}
