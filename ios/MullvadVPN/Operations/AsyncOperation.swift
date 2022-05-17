//
//  AsyncOperation.swift
//  MullvadVPN
//
//  Created by pronebird on 01/06/2020.
//  Copyright © 2020 Mullvad VPN AB. All rights reserved.
//

import Foundation

/// A base implementation of an asynchronous operation
class AsyncOperation: Operation {
    /// A state lock used for manipulating the operation state flags in a thread safe fashion.
    private let stateLock = NSRecursiveLock()

    /// Operation state flags.
    private var _isExecuting = false
    private var _isFinished = false
    private var _isCancelled = false

    final override var isExecuting: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }

        return _isExecuting
    }

    final override var isFinished: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }

        return _isFinished
    }

    final override var isCancelled: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }

        return _isCancelled
    }

    final override var isAsynchronous: Bool {
        return true
    }

    let dispatchQueue: DispatchQueue
    init(dispatchQueue: DispatchQueue? = nil) {
        self.dispatchQueue = dispatchQueue ?? DispatchQueue(label: "AsyncOperation.dispatchQueue")
        super.init()
    }

    final override func start() {
        let underlyingQueue = OperationQueue.current?.underlyingQueue

        if underlyingQueue == dispatchQueue {
            _start()
        } else {
            dispatchQueue.async {
                self._start()
            }
        }
    }

    private func _start() {
        stateLock.lock()
        if _isCancelled {
            stateLock.unlock()
            finish()
        } else {
            setExecuting(true)
            stateLock.unlock()
            main()
        }
    }

    override func main() {
        // Override in subclasses
    }

    final override func cancel() {
        var notifyDidCancel = false

        stateLock.lock()
        if !_isCancelled {
            willChangeValue(for: \.isCancelled)
            _isCancelled = true
            didChangeValue(for: \.isCancelled)

            notifyDidCancel = true
        }
        stateLock.unlock()

        super.cancel()

        if notifyDidCancel {
            dispatchQueue.async {
                self.operationDidCancel()
            }
        }
    }

    func finish() {
        var notifyDidFinish = false

        stateLock.lock()

        if _isExecuting {
           setExecuting(false)
        }

        if !_isFinished {
            willChangeValue(for: \.isFinished)
            _isFinished = true
            didChangeValue(for: \.isFinished)

            notifyDidFinish = true
        }

        stateLock.unlock()

        if notifyDidFinish {
            dispatchQueue.async {
                self.operationDidFinish()
            }
        }
    }

    private func setExecuting(_ value: Bool) {
        willChangeValue(for: \.isExecuting)
        _isExecuting = value
        didChangeValue(for: \.isExecuting)
    }

    func operationDidCancel() {
        // Override in subclasses.
    }

    func operationDidFinish() {
        // Override in subclasses.
    }
}

extension Operation {
    func addDependencies(_ dependencies: [Operation]) {
        for dependency in dependencies {
            addDependency(dependency)
        }
    }
}
