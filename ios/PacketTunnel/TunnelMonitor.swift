//
//  TunnelMonitor.swift
//  PacketTunnel
//
//  Created by pronebird on 09/02/2022.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

import Foundation
import NetworkExtension
import WireGuardKit
import Logging

protocol TunnelMonitorDelegate: AnyObject {
    func tunnelMonitor(_ tunnelMonitor: TunnelMonitor, didChangeStatus newStatus: TunnelMonitor.Status)
}

class TunnelMonitor {
    enum Status {
        case probing
        case noConnection
    }

    /// Error emitted by TunnelMonitor.
    enum Error: Swift.Error {
        case createSocket
        case createRunLoop
        case sendFailure
    }

    private let stateLock = NSLock()
    private let adapter: WireGuardAdapter
    private let queue: DispatchQueue

    // Sender identifier passed along with ICMP packet.
    private let identifier: UInt16 = 757
    private var sequenceNumber: UInt16 = 0
    private var socket: CFSocket?

    private let logger = Logger(label: "TunnelMonitor")
    private var adapterQueryTimer: Timer?

    private weak var _delegate: TunnelMonitorDelegate?
    weak var delegate: TunnelMonitorDelegate? {
        set {
            stateLock.lock()
            _delegate = newValue
            stateLock.unlock()
        }
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return _delegate
        }
    }

    init(queue: DispatchQueue, adapter: WireGuardAdapter) {
        self.queue = queue
        self.adapter = adapter
    }

    deinit {
        stop()
    }

    func start(address: IPv4Address) throws {
        let newSocket = CFSocketCreate(kCFAllocatorDefault, AF_INET, SOCK_DGRAM, IPPROTO_ICMP, 0, nil, nil)

        guard let newSocket = newSocket else {
            throw Error.createSocket
        }

        let flags = CFSocketGetSocketFlags(newSocket)
        if (flags & kCFSocketCloseOnInvalidate) == 0 {
            CFSocketSetSocketFlags(newSocket, flags | kCFSocketCloseOnInvalidate)
        }

        guard let runLoop = CFSocketCreateRunLoopSource(kCFAllocatorDefault, newSocket, 0) else {
            throw Error.createRunLoop
        }

        CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoop, .defaultMode)

        stateLock.lock()
        if let socket = socket {
            CFSocketInvalidate(socket)
        }

        adapterQueryTimer?.invalidate()

        socket = newSocket
        stateLock.unlock()
    }

    func stop() {
        stateLock.lock()
        if let socket = socket {
            CFSocketInvalidate(socket)

            self.socket = nil
        }
        stateLock.unlock()
    }

    private func sendEcho(address: IPv4Address) throws {
        stateLock.lock()
        guard let socket = socket else {
            stateLock.unlock()
            return
        }
        stateLock.unlock()

        var payload = Data(repeating: 0, count: MemoryLayout<TimeInterval>.size)
        payload.withUnsafeMutableBytes { buffer in
            buffer.storeBytes(of: Date().timeIntervalSince1970, as: TimeInterval.self)
        }

        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout.size(ofValue: sa))
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_addr = address.rawValue.withUnsafeBytes { buffer in
            return buffer.bindMemory(to: in_addr.self).baseAddress!.pointee
        }

        let sequenceNumber = nextSequenceNumber()
        let packetData = Self.createPacket(identifier: identifier, sequenceNumber: sequenceNumber, payload: payload)

        let bytesSent = packetData.withUnsafeBytes { dataBuffer -> Int in
            return withUnsafeBytes(of: &sa) { bufferPointer in
                let sockaddrPointer = bufferPointer.bindMemory(to: sockaddr.self).baseAddress!

                return sendto(
                    CFSocketGetNative(socket),
                    dataBuffer.baseAddress!,
                    dataBuffer.count,
                    0,
                    sockaddrPointer,
                    socklen_t(MemoryLayout<sockaddr_in>.size)
                )
            }
        }

        if bytesSent < 1 {
            throw Error.sendFailure
        }
    }

    private func nextSequenceNumber() -> UInt16 {
        stateLock.lock()
        defer { stateLock.unlock() }

        let (partialValue, isOverflow) = sequenceNumber.addingReportingOverflow(1)
        let nextSequenceNumber = isOverflow ? 0 : partialValue

        sequenceNumber = nextSequenceNumber

        return nextSequenceNumber
    }

    private class func createPacket(identifier: UInt16, sequenceNumber: UInt16, payload: Data) -> Data {
        // Create data buffer.
        var data = Data()

        // Create ICMP header struct.
        var icmpHeader = ICMPHeader()
        icmpHeader.type = UInt8(ICMP_ECHO)
        icmpHeader.code = 0
        icmpHeader.checksum = 0
        icmpHeader.identifier = identifier.bigEndian
        icmpHeader.sequenceNumber = sequenceNumber.bigEndian

        // Copy ICMP packet into data buffer.
        withUnsafeBytes(of: &icmpHeader) { buffer in
            data.append(contentsOf: buffer)
        }

        // Append payload.
        data.append(contentsOf: payload)

        // Calculate checksum.
        icmpHeader.checksum = in_chksum(data)

        // Put updated ICMP header containing checksum into the data buffer.
        withUnsafeBytes(of: &icmpHeader) { buffer in
            data.replaceSubrange(0..<buffer.count, with: buffer)
        }

        return data
    }
}

private func in_chksum(_ data: Data) -> UInt16 {
    return data.withUnsafeBytes { buffer in
        let length = buffer.count

        var sum: Int32 = 0

        let isOdd = length  % 2 != 0
        let strideTo = isOdd ? length - 1 : length

        for offset in stride(from: 0, to: strideTo, by: 2) {
            let word = buffer.load(fromByteOffset: offset, as: UInt16.self)
            sum += Int32(word)
        }

        if isOdd {
            let byte = buffer.load(fromByteOffset: length - 1, as: UInt8.self)
            sum += Int32(byte)
        }

        sum = (sum >> 16) + (sum & 0xffff)
        sum += (sum >> 16)

        return UInt16(truncatingIfNeeded: ~sum)
    }
}
