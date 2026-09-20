# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.2.2"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.2/agentsafe-0.2.2-darwin-arm64.tar.gz"
      sha256 "c7d6677fb71baa149b109c7f993b1e7cf006f2b605a1aed61a75feb1b835aca7"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.2/agentsafe-0.2.2-darwin-x64.tar.gz"
      sha256 "a1c211cbf015b15227fb5615f60e01dca4b759b8365996bf90432047dc63076d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.2/agentsafe-0.2.2-linux-arm64.tar.gz"
      sha256 "46a3637412715af2498f51fca12f61cbfdd324caf5a3726a8dee2e6ec8286b8c"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.2/agentsafe-0.2.2-linux-x64.tar.gz"
      sha256 "185753282d973af5be3d8f194348c860047487c7245b859f8e648ba351fa1064"
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
