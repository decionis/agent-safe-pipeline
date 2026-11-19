# The govern formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the static binary the release built for
# this platform; nothing is compiled and no toolchain is needed. The same
# archive is what govern/install.sh downloads and verifies.
class Govern < Formula
  desc "Workflow gate: one Decionis verdict before a CI step runs, with a signed record"
  homepage "https://github.com/decionis/agent-safe-pipeline/tree/master/govern"
  version "2.1.1"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.0/govern-2.1.1-darwin-arm64.tar.gz"
      sha256 "ae5e0d0f23cd23cbb6204caad2ad60543cda008f10f47647b3d99482850eef61"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.0/govern-2.1.1-darwin-x64.tar.gz"
      sha256 "6075b8f7815fc2b1a438489ece2d417fd21f9002d1c6b8213ec145279688ee32"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.0/govern-2.1.1-linux-arm64.tar.gz"
      sha256 "6dd54c3fa7888d48acd8c4193f9e8dd692f00ac3a8fd54fd3b49ce9dc29022ac"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.0/govern-2.1.1-linux-x64.tar.gz"
      sha256 "5981623c79685ebb7185409cf8333cabe6aee8017a68d26989d3eecb060a12d9"
    end
  end

  def install
    libexec.install Dir["*"]
    bin.install_symlink libexec/"govern"
  end

  test do
    assert_equal "govern #{version}", shell_output("#{bin}/govern version").strip
    # A shadow step without a key is inert: the command runs, nothing is
    # recorded, and the step ends with the command's own exit code.
    assert_match "shadow", shell_output("#{bin}/govern run --mode shadow --host generic -- true")
  end
end
