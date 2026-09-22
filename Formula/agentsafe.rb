# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.2.5"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.5/agentsafe-0.2.5-darwin-arm64.tar.gz"
      sha256 "ff7e9c1426753b15f0cddec1fa4da8b5768ae6638ea797c4e2d871758a64dfeb"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.5/agentsafe-0.2.5-darwin-x64.tar.gz"
      sha256 "8706f1b3b4896a8e784dca5aebe8b452761affa2796190f593903b83e0d041c3"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.5/agentsafe-0.2.5-linux-arm64.tar.gz"
      sha256 "627a6c2748e4f66708fb3df09e37b7c9b033da2888f3146a318f33fa797db2eb"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.5/agentsafe-0.2.5-linux-x64.tar.gz"
      sha256 "3c4168b945e2e911c2da85c44c7580612f577e87bc68554276e1b41506cadcb6"
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
