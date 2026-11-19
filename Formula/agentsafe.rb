# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.8.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.0/agentsafe-0.8.0-darwin-arm64.tar.gz"
      sha256 "9e52b4ce9107a7ce7bef7ab269eee607d0c9de4003998a03a308f5cb7e0f6885"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.0/agentsafe-0.8.0-darwin-x64.tar.gz"
      sha256 "7b0b30c253cba770f0d0ee57f16d12521afa1cab1341b25461c488e170cbfa48"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.0/agentsafe-0.8.0-linux-arm64.tar.gz"
      sha256 "4648e12182817ab8ba40b33e252b9cdca078fbf8a34a5286d702307b986fe910"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.6.0/agentsafe-0.8.0-linux-x64.tar.gz"
      sha256 "9125dd6d764da1f937cb848862f786abe5ba328bbb384ea2938bce2820f8f324"
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
