// The client against the in-memory server (kmip.local), in every
// version: test/scenario.goose's checks, as kmip.server answers them.

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
import kmip.local;
import scenario;

fn main() {
    let versions: const u8[:][8] = ["1.0", "1.1", "1.2", "1.3", "1.4", "2.0", "2.1", "auto"];
    for v in versions {
        var c = kmip::local("alice");
        let before = scenario::failures;
        let n = scenario::checks;
        scenario::run(c, v, "local");
        print(v, ": ", scenario::checks - n, " checks, ", scenario::failures - before, " failures");
    }
    print(scenario::checks, " checks, ", scenario::failures, " failures");
    if scenario::failures > 0 { exit(1); }
}
