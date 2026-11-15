# Homebrew cask (scripts/release-mac.sh writes Casks/gimmecores.rb from this file for each
# release): installs GimmeCores.app in Applications, with gmc, gimmecores and gmcd on the PATH.
#
#   brew tap tanuj24/gimmecores https://github.com/tanuj24/gimmecores
#   brew install --cask gimmecores
#
# The app then updates itself (Settings > Updates): every update is signed with the GimmeCores
# update key, which the app checks before installing it.
cask "gimmecores" do
  version "0.1.0"
  sha256 "70308df3f7b4195d6f21c2e8cf494266bad9d8a384620b5fca0e58c02b317a1f"

  url "https://github.com/tanuj24/gimmecores/releases/download/v#{version}/GimmeCores.dmg"
  name "GimmeCores"
  desc "Lend CPU and RAM between your own devices on your local network"
  homepage "https://github.com/tanuj24/gimmecores"

  auto_updates true
  depends_on arch: :arm64
  depends_on macos: :monterey # or newer
  # The formula (built from source) installs the same commands: use one or the other (casks
  # cannot declare a conflict with a formula; brew refuses to link a command twice).

  app "GimmeCores.app"
  binary "#{appdir}/GimmeCores.app/Contents/MacOS/gmc"
  binary "#{appdir}/GimmeCores.app/Contents/MacOS/gimmecores"
  binary "#{appdir}/GimmeCores.app/Contents/MacOS/gmcd"

  # Removing the app also stops the background service the app started and its login item.
  uninstall quit:      "dev.gimmecores.desktop",
            launchctl: "dev.gimmecores.gmcd"

  zap trash: [
    "~/Library/Logs/GimmeCores",
    "~/Library/WebKit/dev.gimmecores.desktop",
    "~/Library/Caches/dev.gimmecores.desktop",
  ]

  caveats <<~EOS
    GimmeCores is not signed with an Apple Developer ID yet. The first time you open it, macOS
    blocks it: open System Settings > Privacy & Security and click "Open Anyway" for
    GimmeCores. Updates the app installs itself are not marked as downloaded, so macOS does
    not block them again.

    Lending stays off until you turn it on. Open GimmeCores and click "Start GimmeCores".
    Your devices, keys and settings (~/Library/Application Support/GimmeCores) are kept when
    the app is removed; delete that folder yourself to remove them.
  EOS
end
