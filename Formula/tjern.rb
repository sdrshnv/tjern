class Tjern < Formula
  desc "A happy little journaling app"
  homepage "https://github.com/sdrshnv/tjern"
  url "https://github.com/sdrshnv/tjern/archive/refs/tags/v0.7.1.tar.gz"
  sha256 "d636a12428d95f93bb3b4605199ec1c89f6851d65bdd854e4b76d4f35c999c73"
  license "GPL-3.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w")
  end

  test do
    system "true"
  end
end
