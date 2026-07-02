import CommonCrypto
import Foundation
import Security

private let srtEncryptedHandshakeVersion5: UInt32 = 5
private let srtEncryptedDestinationSocket: UInt32 = 0
private let srtEncryptedKmReqCommand: UInt16 = 3
private let srtEncryptedStreamIdCommand: UInt16 = 5
private let srtEncryptedDataPacketHeaderSize = 16
private let srtEncryptedEvenKeySpec: UInt8 = 0x08
private let srtEncryptedDefaultKeyLength = 16
private let haiCryptSaltLength = 16
private let haiCryptPbkdf2SaltLength = 8
private let haiCryptPbkdf2IterationCount: UInt32 = 2048
private let haiCryptKmHeaderSize = 16
private let haiCryptWrapKeySignatureSize = 8
private let haiCryptMessageVersion = 1
private let haiCryptMessagePacketTypeKm = 2
private let haiCryptMessageFlagEvenSek: UInt8 = 0x01
private let haiCryptCipherAesCtr: UInt8 = 2
private let haiCryptAuthNone: UInt8 = 0
private let haiCryptStreamEncapsulation: UInt8 = 2

private func srtEncryptedCreateCommonControlPacketHeader(type: UInt16,
                                                         timestamp: UInt32,
                                                         destinationSocketId: UInt32) -> Data
{
    let writer = ByteWriter()
    writer.writeUInt16(0x8000 | type)
    writer.writeUInt16(0)
    writer.writeUInt32(0)
    writer.writeUInt32(timestamp)
    writer.writeUInt32(destinationSocketId)
    return writer.data
}

final class SrtEncryptedSender: @unchecked Sendable {
    weak var delegate: (any SrtSenderDelegate)?
    private let sender: SrtSender
    private let delegateProxy: SrtEncryptedSenderDelegateProxy
    private let crypto: SrtEncryption
    private let streamId: String?
    private let latency: UInt16

    init(streamId: String?, passphrase: String, pbkeylen: String?, latency: UInt16, experimental: Bool) throws {
        self.streamId = streamId
        self.latency = latency
        crypto = try SrtEncryption(passphrase: passphrase, pbkeylen: pbkeylen)
        sender = SrtSender(streamId: streamId, latency: latency, experimental: experimental)
        delegateProxy = SrtEncryptedSenderDelegateProxy()
        delegateProxy.owner = self
        sender.delegate = delegateProxy
    }

    func start() {
        sender.start()
    }

    func stop() {
        sender.stop()
    }

    func newDataPacket(payload: UnsafeRawBufferPointer) -> SrtDataPacket {
        sender.newDataPacket(payload: payload)
    }

    func enqueue(packet: SrtDataPacket, now: ContinuousClock.Instant) {
        sender.enqueue(packet: packet, now: now)
    }

    func send(now: ContinuousClock.Instant) {
        sender.send(now: now)
    }

    func input(packet: Data) {
        sender.input(packet: packet)
    }

    func getPerformanceData() -> SrtPerformanceData? {
        sender.getPerformanceData()
    }

    fileprivate func output(packet: Data) {
        if isSrtDataPacket(packet: packet) {
            do {
                delegate?.srtSenderOutput(packet: try crypto.encrypt(packet: packet))
            } catch {
                logger.info("srt-sender: Encryption error: \(error)")
                sender.stop()
            }
        } else if isSrtConclusionHandshake(packet: packet) {
            delegate?.srtSenderOutput(packet: createEncryptedConclusionHandshake(from: packet))
        } else {
            delegate?.srtSenderOutput(packet: packet)
        }
    }

    private func isSrtConclusionHandshake(packet: Data) -> Bool {
        guard packet.count >= 64, !isSrtDataPacket(packet: packet), getSrtControlPacketType(packet: packet) == 0 else {
            return false
        }
        return packet.getUInt32Be(offset: 36) == 0xFFFF_FFFF
    }

    private func createEncryptedConclusionHandshake(from packet: Data) -> Data {
        let writer = ByteWriter()
        writer.writeBytes(srtEncryptedCreateCommonControlPacketHeader(
            type: 0,
            timestamp: packet.getUInt32Be(offset: 8),
            destinationSocketId: srtEncryptedDestinationSocket
        ))
        writer.writeUInt32(srtEncryptedHandshakeVersion5)
        writer.writeUInt16(0)
        writer.writeUInt16(encryptedHandshakeExtensionFlags())
        writer.writeUInt32(packet.getUInt32Be(offset: 24))
        writer.writeUInt32(packet.getUInt32Be(offset: 28))
        writer.writeUInt32(packet.getUInt32Be(offset: 32))
        writer.writeUInt32(packet.getUInt32Be(offset: 36))
        writer.writeUInt32(packet.getUInt32Be(offset: 40))
        writer.writeUInt32(packet.getUInt32Be(offset: 44))
        writer.writeBytes(packet[48 ..< 64])
        writer.writeBytes(createHandshakeExtension(command: 1, data: createHsReq()))
        if let streamId {
            writer.writeBytes(createHandshakeExtension(command: srtEncryptedStreamIdCommand,
                                                       data: encodeStreamId(streamId: streamId)))
        }
        writer.writeBytes(createHandshakeExtension(command: srtEncryptedKmReqCommand, data: crypto.keyMaterialMessage))
        return writer.data
    }

    private func createHsReq() -> Data {
        let writer = ByteWriter()
        writer.writeUInt32(0x0001_0503)
        writer.writeUInt32(0xBF)
        writer.writeUInt16(latency)
        writer.writeUInt16(latency)
        return writer.data
    }

    private func encryptedHandshakeExtensionFlags() -> UInt16 {
        var flags: UInt16 = 0x0003
        if streamId != nil {
            flags |= 0x0004
        }
        return flags
    }

    private func createHandshakeExtension(command: UInt16, data: Data) -> Data {
        let writer = ByteWriter()
        writer.writeUInt16(command)
        writer.writeUInt16(UInt16((data.count + 3) / 4))
        writer.writeBytes(data)
        if !data.count.isMultiple(of: 4) {
            writer.writeBytes(Data(count: 4 - (data.count % 4)))
        }
        return writer.data
    }

    private func encodeStreamId(streamId: String) -> Data {
        var streamId = streamId.utf8Data
        let paddingLength = 4 - (streamId.count % 4)
        if paddingLength < 4 {
            streamId += Data(repeating: 0, count: paddingLength)
        }
        for offset in stride(from: 0, to: streamId.count, by: 4) {
            streamId[offset ..< offset + 4] = Data(streamId[offset ..< offset + 4].reversed())
        }
        return streamId
    }
}

private final class SrtEncryptedSenderDelegateProxy: SrtSenderDelegate {
    weak var owner: SrtEncryptedSender?

    func srtSenderConnected() {
        owner?.delegate?.srtSenderConnected()
    }

    func srtSenderDisconnected() {
        owner?.delegate?.srtSenderDisconnected()
    }

    func srtSenderOutput(packet: Data) {
        owner?.output(packet: packet)
    }
}

struct SrtEncryption {
    let keyMaterialMessage: Data
    private let sek: Data
    private let salt: Data
    private let dataEncryptor: AesEcbEncryptor

    init(passphrase: String, pbkeylen: String?) throws {
        let keyLength = try Self.parseKeyLength(pbkeylen: pbkeylen)
        salt = try Self.randomData(count: haiCryptSaltLength)
        sek = try Self.randomData(count: keyLength)
        dataEncryptor = try AesEcbEncryptor(key: sek)
        let kek = try Self.deriveKey(passphrase: passphrase, salt: salt, keyLength: keyLength)
        let wrappedSek = try Self.wrapKey(kek: kek, plaintext: sek)
        keyMaterialMessage = Self.createKeyMaterialMessage(salt: salt, sekLength: keyLength, wrappedSek: wrappedSek)
    }

    func encrypt(packet: Data) throws -> Data {
        guard packet.count >= srtEncryptedDataPacketHeaderSize else {
            throw "SRT packet too short"
        }
        var encrypted = packet
        encrypted[4] |= srtEncryptedEvenKeySpec
        let iv = createCtrIv(packet: encrypted)
        let payload = encrypted[srtEncryptedDataPacketHeaderSize ..< encrypted.count]
        let encryptedPayload = try aesCtrCrypt(iv: iv, data: Data(payload))
        encrypted.replaceSubrange(srtEncryptedDataPacketHeaderSize ..< encrypted.count, with: encryptedPayload)
        return encrypted
    }

    private func createCtrIv(packet: Data) -> Data {
        var iv = Data(count: kCCBlockSizeAES128)
        iv[10 ..< 14] = packet[0 ..< 4]
        for index in 0 ..< 14 {
            iv[index] ^= salt[index]
        }
        return iv
    }

    static func parseKeyLength(pbkeylen: String?) throws -> Int {
        guard let pbkeylen, !pbkeylen.isEmpty else {
            return srtEncryptedDefaultKeyLength
        }
        guard let keyLength = Int(pbkeylen), [16, 24, 32].contains(keyLength) else {
            throw "Invalid pbkeylen \(pbkeylen)"
        }
        return keyLength
    }

    private static func createKeyMaterialMessage(salt: Data, sekLength: Int, wrappedSek: Data) -> Data {
        var message = Data(count: haiCryptKmHeaderSize)
        message[0] = UInt8((haiCryptMessageVersion << 4) | haiCryptMessagePacketTypeKm)
        message[1] = 0x20
        message[2] = 0x29
        message[3] = haiCryptMessageFlagEvenSek
        message[8] = haiCryptCipherAesCtr
        message[9] = haiCryptAuthNone
        message[10] = haiCryptStreamEncapsulation
        message[14] = UInt8(salt.count / 4)
        message[15] = UInt8(sekLength / 4)
        message += salt
        message += wrappedSek
        return message
    }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let result = data.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, count, pointer.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw "Failed to generate random data"
        }
        return data
    }

    private static func deriveKey(passphrase: String, salt: Data, keyLength: Int) throws -> Data {
        var key = Data(count: keyLength)
        let pbkdf2Salt = salt.suffix(haiCryptPbkdf2SaltLength)
        let result = key.withUnsafeMutableBytes { keyPointer in
            pbkdf2Salt.withUnsafeBytes { saltPointer in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passphrase,
                    passphrase.utf8.count,
                    saltPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    pbkdf2Salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                    haiCryptPbkdf2IterationCount,
                    keyPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    keyLength
                )
            }
        }
        guard result == kCCSuccess else {
            throw "PBKDF2 failed"
        }
        return key
    }

    static func wrapKey(kek: Data, plaintext: Data) throws -> Data {
        guard plaintext.count.isMultiple(of: 8), plaintext.count >= 16 else {
            throw "Invalid key wrap input size"
        }
        var a = Data(repeating: 0xA6, count: haiCryptWrapKeySignatureSize)
        var r = stride(from: 0, to: plaintext.count, by: 8).map { Data(plaintext[$0 ..< $0 + 8]) }
        let n = r.count
        for j in 0 ..< 6 {
            for i in 0 ..< n {
                let block = try aesEcbEncrypt(key: kek, data: a + r[i])
                a = Data(block[0 ..< 8])
                let t = UInt64(j * n + i + 1)
                for offset in 0 ..< 8 {
                    a[offset] ^= UInt8((t >> UInt64(8 * (7 - offset))) & 0xFF)
                }
                r[i] = Data(block[8 ..< 16])
            }
        }
        return r.reduce(a) { $0 + $1 }
    }

    private func aesCtrCrypt(iv: Data, data: Data) throws -> Data {
        var counter = iv
        var output = Data(count: data.count)
        var offset = 0
        while offset < data.count {
            let keyStream = try dataEncryptor.encrypt(block: counter)
            let blockLength = min(kCCBlockSizeAES128, data.count - offset)
            for index in 0 ..< blockLength {
                output[offset + index] = data[offset + index] ^ keyStream[index]
            }
            Self.incrementCounter(&counter)
            offset += blockLength
        }
        return output
    }

    private static func incrementCounter(_ counter: inout Data) {
        for index in stride(from: counter.count - 1, through: 0, by: -1) {
            counter[index] &+= 1
            if counter[index] != 0 {
                break
            }
        }
    }

    private static func aesEcbEncrypt(key: Data, data: Data) throws -> Data {
        var output = Data(count: data.count + kCCBlockSizeAES128)
        let outputCapacity = output.count
        var outputLength = 0
        let status = output.withUnsafeMutableBytes { outputPointer in
            data.withUnsafeBytes { dataPointer in
                key.withUnsafeBytes { keyPointer in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyPointer.baseAddress!,
                        key.count,
                        nil,
                        dataPointer.baseAddress!,
                        data.count,
                        outputPointer.baseAddress!,
                        outputCapacity,
                        &outputLength
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw "AES encrypt failed"
        }
        output.removeSubrange(outputLength ..< output.count)
        return output
    }
}

private final class AesEcbEncryptor {
    private let cryptor: CCCryptorRef

    init(key: Data) throws {
        var cryptor: CCCryptorRef?
        let status = key.withUnsafeBytes { keyPointer in
            CCCryptorCreate(
                CCOperation(kCCEncrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                keyPointer.baseAddress!,
                key.count,
                nil,
                &cryptor
            )
        }
        guard status == kCCSuccess, let cryptor else {
            throw "AES encryptor creation failed"
        }
        self.cryptor = cryptor
    }

    deinit {
        CCCryptorRelease(cryptor)
    }

    func encrypt(block: Data) throws -> Data {
        var output = Data(count: block.count + kCCBlockSizeAES128)
        let outputCapacity = output.count
        var outputLength = 0
        let status = output.withUnsafeMutableBytes { outputPointer in
            block.withUnsafeBytes { blockPointer in
                CCCryptorUpdate(
                    cryptor,
                    blockPointer.baseAddress!,
                    block.count,
                    outputPointer.baseAddress!,
                    outputCapacity,
                    &outputLength
                )
            }
        }
        guard status == kCCSuccess else {
            throw "AES encrypt failed"
        }
        output.removeSubrange(outputLength ..< output.count)
        return output
    }
}
