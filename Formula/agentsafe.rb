# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.2.4"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.4/agentsafe-0.2.4-darwin-arm64.tar.gz"
      sha256 "e6a2135e42b072d6a1d7a98346cc4b9c24c6edd12f9b366f00cd43e59f52dea7"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.4/agentsafe-0.2.4-darwin-x64.tar.gz"
      sha256 "e82d3e58af00818879faaa0dff51c5c6f06b13a9b84951b79659194c2716f0b2"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.4/agentsafe-0.2.4-linux-arm64.tar.gz"
      sha256 "a602090c3f07d2816441013b6fbc6ff29a6814798253a3ff64f5ad17e8eee49f"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.4/agentsafe-0.2.4-linux-x64.tar.gz"
      sha256 "27716e3f356d6ce9c46af771d57eccc8f64bc2f4591ce12bb41b1db88d8b86ff"
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
