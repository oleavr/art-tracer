## Build

First make sure you have a Frida checkout built for android-x86, somewhere
outside the art-tracer repo:

    git clone --recurse-submodules https://github.com/frida/frida.git
    cd frida
    make build/frida-android-x86/lib/pkgconfig/frida-core-1.0.pc

Then in here:

    export FRIDA=/path/to/frida/checkout
    make build

## Deploy

    make deploy
