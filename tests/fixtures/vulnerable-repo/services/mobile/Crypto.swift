import CryptoKit
import Foundation

enum MobileCrypto {
    // at-rest encryption — AES-GCM (quantum-safe symmetric)
    static func seal(_ data: Data, key: SymmetricKey) throws -> Data {
        try AES.GCM.seal(data, using: key).combined!
    }

    // device attestation — P-256 signature
    static func sign(_ data: Data, key: P256.Signing.PrivateKey) throws -> Data {
        try key.signature(for: data).rawRepresentation
    }

    // legacy checksum — MD5 (Insecure)
    static func legacyChecksum(_ data: Data) -> String {
        Insecure.MD5.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
