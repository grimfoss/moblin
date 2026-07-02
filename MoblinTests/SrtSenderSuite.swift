import Foundation
@testable import Moblin
import Testing

private class ModelMock {
    private let connected = MessageQueue<Void>()
    private let disconnected = MessageQueue<Void>()
    private let packets = MessageQueue<String>()

    func waitForConnected() async {
        await connected.get()
    }

    func waitForDisconnected() async {
        await disconnected.get()
    }

    func waitForPacket() async -> String {
        await packets.get()
    }
}

extension ModelMock: SrtSenderDelegate {
    func srtSenderConnected() {
        connected.put(())
    }

    func srtSenderDisconnected() {
        disconnected.put(())
    }

    func srtSenderOutput(packet: Data) {
        packets.put(packet.hexString())
    }
}

struct SrtSenderSuite {
    @Test
    func connectDisconnect() async throws {
        let sender = SrtSender(streamId: "1234", latency: 2000, experimental: false)
        let model = ModelMock()
        sender.delegate = model
        sender.start()
        _ = await checkInductionHandshake(packet: model.waitForPacket())
        try sender.input(packet: createInductionHandshake())
        _ = await checkConclusionHandshake(packet: model.waitForPacket())
        try sender.input(packet: createConclusionHandshake())
        await model.waitForConnected()
        sender.send(now: .now.advanced(by: .seconds(6)))
        await model.waitForDisconnected()
    }

    @Test
    func encryptedConclusionHandshakeContainsKeyMaterial() async throws {
        let sender = try SrtEncryptedSender(streamId: "1234",
                                            passphrase: "0123456789abcdef",
                                            pbkeylen: "16",
                                            latency: 2000,
                                            experimental: false)
        let model = ModelMock()
        sender.delegate = model
        sender.start()
        _ = await checkInductionHandshake(packet: model.waitForPacket())
        try sender.input(packet: createInductionHandshake())
        let packet = await model.waitForPacket()
        #expect(packet.count == 296)
        #expect(packet.substring(begin: 128, end: 136) == "00010003")
        #expect(packet.substring(begin: 160, end: 168) == "00050001")
        #expect(packet.substring(begin: 176, end: 184) == "0003000e")
        #expect(packet.substring(begin: 184, end: 192) == "12202901")
        #expect(packet.substring(begin: 200, end: 208) == "02000200")
        #expect(packet.substring(begin: 212, end: 216) == "0404")
    }

    @Test
    func aesKeyWrapVector() throws {
        let kek = try Data(hexString: "000102030405060708090a0b0c0d0e0f")
        let plaintext = try Data(hexString: "00112233445566778899aabbccddeeff")
        let wrapped = try SrtEncryption.wrapKey(kek: kek, plaintext: plaintext)
        #expect(wrapped.hexString() == "1fa68b0a8112b447aeF34bd8fb5a7b82 9d3e862371d2cfe5"
            .lowercased()
            .replacingOccurrences(of: " ", with: ""))
    }

    private func checkInductionHandshake(packet: String) -> (UInt32, UInt32) {
        #expect(packet.count == 128)
        #expect(packet.substring(begin: 0, end: 16) == "8000000000000000")
        let timestamp = UInt32(packet.substring(begin: 16, end: 24), radix: 16)!
        #expect(packet.substring(begin: 24, end: 48) == "000000000000000400000002")
        let sequenceNumber = UInt32(packet.substring(begin: 48, end: 56), radix: 16)!
        #expect(packet.substring(begin: 56, end: 80) == "000005dc0000200000000001")
        #expect(packet.substring(begin: 88, end: 128) == "000000000100007f000000000000000000000000")
        return (timestamp, sequenceNumber)
    }

    private func createInductionHandshake() throws -> Data {
        try Data(hexString: """
        80000000000000000000000000000000000000040000000200000fe6000005dc\
        00002000000000012ab1f77c000000000100007f000000000000000000000000
        """)
    }

    private func checkConclusionHandshake(packet: String) -> (UInt32, UInt32) {
        #expect(packet.count == 176)
        #expect(packet.substring(begin: 0, end: 16) == "8000000000000000")
        let timestamp = UInt32(packet.substring(begin: 16, end: 24), radix: 16)!
        #expect(packet.substring(begin: 24, end: 48) == "000000000000000500000005")
        let sequenceNumber = UInt32(packet.substring(begin: 48, end: 56), radix: 16)!
        #expect(packet
            .substring(begin: 56, end: 176) ==
            """
            000005dc00002000ffffffff2ab1f77c000000000100007f000000000000\
            0000000000000001000300010503000000bf07d007d00005000134333231
            """)
        return (timestamp, sequenceNumber)
    }

    private func createConclusionHandshake() throws -> Data {
        try Data(hexString: """
        800000000000000000000000000000000000000500000005000000000000\
        05dc00002000ffffffff2ab1f77c000000000100007f0000000000000000\
        000000000001000300010503000000bf07d007d00005000134333231
        """)
    }
}
