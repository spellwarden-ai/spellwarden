curl -fsSL https://get.example.com/install.sh -o install.sh
sha256sum -c install.sh.sha256 &&
  sh install.sh
