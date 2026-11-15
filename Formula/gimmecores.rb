# Homebrew formula: builds GimmeCores from source on your machine.
#
#   brew tap tanuj24/gimmecores https://github.com/tanuj24/gimmecores
#   brew install --HEAD gimmecores
#   brew upgrade --fetch-HEAD gimmecores      # later, to update
#
# Building locally means nothing downloaded is a pre-built binary, so macOS has no
# quarantine warning to show. (Signed, notarized releases come later.)
class Gimmecores < Formula
  desc "Lend CPU and RAM between your own devices on your local network"
  homepage "https://github.com/tanuj24/gimmecores"
  license "Apache-2.0"
  head "https://github.com/tanuj24/gimmecores.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "build", "--release", "--locked", "-p", "gimmecores-cli"
    bin.install "target/release/gmc", "target/release/gmcd", "target/release/gimmecores"

    if OS.mac?
      # The desktop app, with its own copies of gmcd and gmc inside.
      ENV["GMC_NO_DMG"] = "1"
      system "packaging/macos/build-app.sh"
      prefix.install "dist/GimmeCores.app"
    end
  end

  # `brew services start gimmecores` runs gmcd in the background and at login. Use this or
  # the app's "Start GimmeCores", not both (the app notices and leaves this one alone).
  service do
    run opt_bin/"gmcd"
    # launchd's default PATH would hide Docker Desktop and Homebrew's tools from tasks.
    environment_variables PATH: std_service_path_env
    keep_alive successful_exit: false
    # Tasks inherit how macOS schedules this service. Measured on an M2 Max: as a background
    # job they ran 6 to 15 times slower (efficiency cores only), as a standard one (the
    # default) work on several cores ran at half speed. Interactive runs them like any
    # program you start yourself.
    process_type :interactive
    log_path var/"log/gimmecores.log"
    error_log_path var/"log/gimmecores.log"
  end

  def caveats
    s = <<~EOS
      Lending stays off until you turn it on (`gmc lend on`, or in the app).
      Start the background daemon with either:
        brew services start gimmecores
      or the desktop app's "Start GimmeCores" button.
    EOS
    if OS.mac?
      s += <<~EOS

        The desktop app is in #{opt_prefix}/GimmeCores.app. To open it from Launchpad
        and Spotlight, link it into your Applications folder (the link follows upgrades):
          ln -sfn #{opt_prefix}/GimmeCores.app ~/Applications/GimmeCores.app
        `brew upgrade --fetch-HEAD gimmecores` updates it. For the released app, installed in
        Applications and updating itself, use the cask instead (not both):
          brew services stop gimmecores; brew uninstall gimmecores
          brew install --cask gimmecores
      EOS
    else
      s += <<~EOS

        The sandbox runtime needs bubblewrap (e.g. `sudo apt install bubblewrap`), and
        presence checks need polkit: see packaging/linux/install.sh.
      EOS
    end
    s
  end

  test do
    assert_match "gmc", shell_output("#{bin}/gmc --help")
    assert_match "gmcd", shell_output("#{bin}/gmcd --help")
  end
end
