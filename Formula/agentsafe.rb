# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.9.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.1/agentsafe-0.9.0-darwin-arm64.tar.gz"
      sha256 "e3d52f8bf1348bb83dda1e0aa87d1f9b9983a05d66b8a5516bc2529e46276dba"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.1/agentsafe-0.9.0-darwin-x64.tar.gz"
      sha256 "ec4d02b7ac075e74194a7d8cfa651fc92d57634acc375a4b1dac3e861702e5a9"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.1/agentsafe-0.9.0-linux-arm64.tar.gz"
      sha256 "a2400942150de48a1fa535ed91e0732b8b1f8b90c08ff9a4cdec4d44e4f64b4a"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.1/agentsafe-0.9.0-linux-x64.tar.gz"
      sha256 "44f96a7811bd5790132d8bae8dc62f4ee9bbfa5ab6e2f984ebffd2261f9e378a"
    end
  end

  def install
    libexec.install Dir["*"]
    bin.install_symlink libexec/"agentsafe"
  end

  test do
    assert_equal version.to_s, shell_output("#{bin}/agentsafe version").strip
    # The doctor passes offline against the demo authority: the binary, the
    # configuration and the evidence settings are checked, the network is not.
    assert_match "Ready to govern.", shell_output("#{bin}/agentsafe doctor --upstream http://127.0.0.1:1 --no-network")
  end
end
