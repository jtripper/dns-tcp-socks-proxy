# Maintainer: Jack Tripper <jack@jtripper.net>
pkgname=tcpdnsproxy
pkgver=20130128
pkgrel=1
pkgdesc="A transparent DNS-over-SOCKS proxy for use with transparent SOCKS proxies."
arch=("any")
makedepends=('git')
url="http://github.com/jtRIPper/dns-tcp-socks-proxy"
license=('GPL')
provides=('dns_proxy' 'tcpdnsproxy.service')
_gitroot="git://github.com/jtRIPper/dns-tcp-socks-proxy.git"
_gitname="dns-tcp-socks-proxy"

build() {
  cd "$srcdir"
  if [ -d $_gitname ] ; then
    cd $_gitname && git pull origin
    msg "The local files are updated."
  else
    git clone $_gitroot $_gitname
  fi			

  cd "$srcdir/$_gitname"
  make
}

package() {
  cd "$srcdir/$_gitname"
  install -Dm755 dns_proxy "$pkgdir/usr/bin/dns_proxy"
  sed -i 's#resolv\.conf#/etc/dns_proxy/resolv.conf#g' dns_proxy.conf
  install -Dm644 dns_proxy.conf "$pkgdir/etc/dns_proxy/dns_proxy.conf"
  install -Dm644 resolv.conf "$pkgdir/etc/dns_proxy/resolv.conf"
  install -Dm755 arch_files/tcpdnsproxy.service "$pkgdir/usr/lib/systemd/system/tcpdnsproxy.service"
}
