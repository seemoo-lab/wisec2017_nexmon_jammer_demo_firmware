![NexMon logo](https://github.com/seemoo-lab/nexmon/raw/master/gfx/nexmon.png)

# WiSec 2017 Nexmon Jammer

On the 10th ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec 2017) 
we published a demo on "Demonstrating Reactive Smartphone-Based Jamming" based on the jammer 
developed for our publication "Massive Reactive Smartphone-Based Jamming using Arbitrary Waveforms
and Adaptive Power Control". This repository contains source code required to rebuild the firmware
used during our demonstartion. Additionally, it allows fellow researches to base their own
research on our results.

# Extract from our License

Any use of the Software which results in an academic publication or
other publication which includes a bibliography must include
citations to the nexmon project (1) and the paper cited under (2):

1. "Matthias Schulz, Daniel Wegemer and Matthias Hollick. Nexmon:
    The C-based Firmware Patching Framework. https://nexmon.org"

2. "Matthias Schulz, Francesco Gringoli, Daniel Steinmetzer, Michael
    Koch and Matthias Hollick. Massive Reactive Smartphone-Based
    Jamming using Arbitrary Waveforms and Adaptive Power Control.
    Proceedings of the 10th ACM Conference on Security and Privacy
    in Wireless and Mobile Networks (WiSec 2017), July 2017."

# Getting Started

To compile the source code, you are required to first checkout a copy of the original nexmon
repository that contains our C-based patching framework for Wi-Fi firmwares. Than, you checkout
this repository as one of the sub-projects in the corresponding patches sub-directory. This 
allows you to build and compile all the firmware patches required to repeat our experiments.
The following steps will get you started on Xubuntu 16.04 LTS:

1. Install some dependencies: `sudo apt-get install git gawk qpdf adb`
2. **Only necessary for x86_64 systems**, install i386 libs: 

  ```
  sudo dpkg --add-architecture i386
  sudo apt-get update
  sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386
  ```
3. Clone the nexmon base repository: `git clone https://github.com/seemoo-lab/nexmon.git`.
4. Download and extract Android NDK r11c (use exactly this version!).
5. Export the NDK_ROOT environment variable pointing to the location where you extracted the ndk so that it can be found by our build environment.
6. Navigate to the previously cloned nexmon directory and execute `source setup_env.sh` to set a couple of environment variables.
7. Run `make` to extract ucode, templateram and flashpatches from the original firmwares.
8. Navigate to utilities and run `make` to build all utilities such as nexmon.
9. Attach your rooted Nexus 5 smartphone running stock firmware version 6.0.1 (M4B30Z, Dec 2016).
10. Run `make install` to install all the built utilities on your phone.
11. Navigate to patches/bcm4339/6_37_34_43/ and clone this repository: `git clone https://github.com/seemoo-lab/wisec2017_nexmon_jammer_demo_firmware.git`
12. Enter the created subdirectory wisec2017_nexmon_jammer_demo_firmware and run `make` to compile our firmware patch. You may integrate the resulting firmware file into our Android app.

# References

* Matthias Schulz, Efstathios Deligeorgopoulos, Matthias Hollick and Francesco Gringoli. **DEMO: Demonstrating Reactive Smartphone-Based Jamming**. Proceedings of the *10th ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec 2017)*, July 2017.
* Matthias Schulz, Francesco Gringoli, Daniel Steinmetzer, Michael Koch and Matthias Hollick. **Massive Reactive Smartphone-Based Jamming using Arbitrary Waveforms and Adaptive Power Control**. Proceedings of the *10th ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec 2017)*, July 2017.
* Matthias Schulz, Daniel Wegemer and Matthias Hollick. **Nexmon: The C-based Firmware Patching Framework**. https://nexmon.org

# Contact

* [Matthias Schulz](https://seemoo.tu-darmstadt.de/mschulz) <mschulz@seemoo.tu-darmstadt.de>
* [Francesco Gringoli](http://netweb.ing.unibs.it/~gringoli/) <francesco.gringoli@unibs.it>

# Powered By

## Secure Mobile Networking Lab (SEEMOO)
<a href="https://www.seemoo.tu-darmstadt.de">![SEEMOO logo](https://github.com/seemoo-lab/nexmon/raw/master/gfx/seemoo.png)</a>
## Networked Infrastructureless Cooperation for Emergency Response (NICER)
<a href="https://www.nicer.tu-darmstadt.de">![NICER logo](https://github.com/seemoo-lab/nexmon/raw/master/gfx/nicer.png)</a>
## Multi-Mechanisms Adaptation for the Future Internet (MAKI)
<a href="http://www.maki.tu-darmstadt.de/">![MAKI logo](https://github.com/seemoo-lab/nexmon/raw/master/gfx/maki.png)</a>
