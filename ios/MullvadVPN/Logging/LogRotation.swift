//
//  LogRotation.swift
//  MullvadVPN
//
//  Created by pronebird on 02/08/2020.
//  Copyright © 2020 Mullvad VPN AB. All rights reserved.
//

import Foundation

enum LogRotation {

    enum Error: ChainedError {
        case noSourceLogFile
        case moveSourceLogFile(Swift.Error)

        var errorDescription: String? {
            switch self {
            case .noSourceLogFile:
                return "Source log file does not exist."
            case .moveSourceLogFile:
                return "Failure to move the source log file to backup."
            }
        }
    }

    static func rotateLog(logsDirectory: URL, logFileName: String) -> Result<(), Error> {
        let fileManager = FileManager.default
        let source = logsDirectory.appendingPathComponent(logFileName)
        let backup = source.deletingPathExtension().appendingPathExtension("old.log")

        return Result { _ = try fileManager.replaceItemAt(backup, withItemAt: source) }
            .mapError { (error) -> Error in
                // FileManager returns a very obscure error chain so we need to traverse it to find
                // the root cause of the error.
                var errorCursor: Swift.Error? = error
                let cocoaErrorIterator = AnyIterator { () -> CocoaError? in
                    if let cocoaError = errorCursor as? CocoaError {
                        errorCursor = cocoaError.underlying
                        return cocoaError
                    } else {
                        errorCursor = nil
                        return nil
                    }
                }

                while let fileError = cocoaErrorIterator.next() {
                    // .fileNoSuchFile is returned when both backup and source log files do not exist
                    // .fileReadNoSuchFile is returned when backup exists but source log file does not
                    if fileError.code == .fileNoSuchFile || fileError.code == .fileReadNoSuchFile,
                        fileError.url == source {
                        return .noSourceLogFile
                    }
                }

                return .moveSourceLogFile(error)
        }
    }
}
