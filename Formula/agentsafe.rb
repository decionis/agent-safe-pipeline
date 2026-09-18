# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.2.0/agentsafe-0.1.0-darwin-arm64.tar.gz"
      sha256 "7729507b1cf7dac6de677c88f8bfbe00d92c1dd817c89f40158d7886ce874843"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.2.0/agentsafe-0.1.0-darwin-x64.tar.gz"
      sha256 "697204ab1a222ae3f413062b846a7138c3bc7623115cd4f653cfada3a7173cd1"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.2.0/agentsafe-0.1.0-linux-arm64.tar.gz"
      sha256 "157a4174bbc469d3c445598701060e7cc44493ecbaa88b39f7f7cd3ccc8faae8"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.2.0/agentsafe-0.1.0-linux-x64.tar.gz"
      sha256 "d2eb33eeb834553465efd343b013ee29df183f0bcea68efdfd72ccc37d00e723"
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
