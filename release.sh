#!/bin/sh
# $Id: release.sh 4397 2004-12-02 19:47:46Z lha $

if [ X"$1" = X ]; then
    echo "missing version argument"
    echo "usage: release.sh 0.5"
    exit 1
fi

ver="$1"
cver=$(echo ${ver} | sed 's/\./_/g')
svnroot=svn+ssh://radar.it.su.se/local/svn/devel/mod_spnego
distsite=/afs/su.se/home/l/h/lha/Public/mod_spnego
sn=mod_spnego-${cver}
rn=mod_spnego-${ver}

rm -rf mod_spnego-${ver}

svn cp -m "release $ver" ${svnroot}/trunk ${svnroot}/tags/${sn}

svn export ${svnroot}/tags/${sn} ${rn} || exit 1

echo "version ${ver}" > ${rn}/version

rm -f ${rn}/release.sh

tar cf - ${rn} | gzip -9 > ${rn}.tar.gz

test -d $HOME/.gnupg && gpg -ba ${rn}.tar.gz

echo "cp ${rn}.tar.gz* ${rn}/README ${distsite}/."
