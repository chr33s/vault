import Foundation
import VaultCommands

exit(await VaultCommands.main(Array(CommandLine.arguments.dropFirst())))
