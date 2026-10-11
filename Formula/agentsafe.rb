# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.3.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.6/agentsafe-0.3.0-darwin-arm64.tar.gz"
      sha256 "6ef6788e05886d6fca3fd6c78c803c0f151e09c34340a5d5d959a2388d2131b9"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.6/agentsafe-0.3.0-darwin-x64.tar.gz"
      sha256 "c64e060f6f8fcd0252cace54d1bbd7898163458c4b4ab6420ba0259a544d3ad6"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.6/agentsafe-0.3.0-linux-arm64.tar.gz"
      sha256 "0e91b77a8c5a9f9e51307e6268469ac43e9159d19fdec606dab6f6a5a6b2bcaa"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.6/agentsafe-0.3.0-linux-x64.tar.gz"
      sha256 "059cc75f58c76daf9613fb7719366538ed6a5ec4b440f7a44a8ebf254fd4781c"
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
