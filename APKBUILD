pkgname=casrap
pkgver=0.1.0
pkgrel=0
pkgdesc="casrap"
url="https://www.casrap.com"
arch="all"
license="MIT"
depends="uwsgi uwsgi-python3 uwsgi-http python3 py3-pip gcc python3-dev linux-headers musl-dev make"
makedepends=""
checkdepends=""
install="$pkgname.post-install"
subpackages=""
source="
        $pkgname-dev.zip
        $pkgname.initd
        "
builddir="$srcdir/casrap-dev/"

build() {
        :
}

check() {
        :
}

package() {

        install -Dm755 -d "$pkgdir"/etc/$pkgname/

        install -Dm755 -d "$pkgdir"/usr/lib/$pkgname/src

        install -Dm755 -d "$pkgdir"/usr/lib/$pkgname/services

        install -Dm755 src/*.py "$pkgdir"/usr/lib/$pkgname/src

        install -Dm755 requirements.txt "$pkgdir"/usr/lib/$pkgname/

        install -m755 -D "$srcdir"/$pkgname.initd "$pkgdir"/etc/init.d/$pkgname

}