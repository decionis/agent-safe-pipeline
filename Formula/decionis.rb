class Decionis < Formula
  desc "Economic circuit breakers and execution gates for autonomous systems"
  homepage "https://decionis.com"
  url "https://registry.npmjs.org/decionis/-/decionis-0.2.0.tgz"
  sha256 "bf0ce8f30e5e950d6e95c3628629b0f41408509775762cc1a368a690e07bdb96"
  license "UNLICENSED"

  depends_on "node@20"

  def install
    system "npm", "install", *std_npm_install_args(libexec)
    bin.install_symlink libexec/"bin/decionis"
  end

  test do
    assert_match "decionis", shell_output("#{bin}/decionis --help")
  end
end
