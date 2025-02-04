#!/bin/sh

pushd $(dirname "$0") > /dev/null

clang Source/mdnsarr.c -o /tmp/mdnsarr

sudo mkdir -p /usr/local/mdnsarr/sbin
sudo chown -R root:wheel /usr/local/mdnsarr
sudo chmod -R 755 /usr/local/mdnsarr
sudo cp /tmp/mdnsarr /usr/local/mdnsarr/sbin
sudo codesign -s - -f /usr/local/mdnsarr/sbin/mdnsarr

sudo chmod -R 755 /usr/local/mdnsarr/sbin/mdnsarr

if [ ! -f /etc/mdnsarr ]; then
    sudo cp Resources/example.conf /etc/mdnsarr
fi

sudo cp Resources/com.ricciadams.mdnsarr.plist /Library/LaunchDaemons
sudo launchctl unload /Library/LaunchDaemons/com.ricciadams.mdnsarr.plist
sudo launchctl load /Library/LaunchDaemons/com.ricciadams.mdnsarr.plist
sudo killall mdnsarr

popd > /dev/null
