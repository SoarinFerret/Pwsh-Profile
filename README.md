# My PowerShell Profile

My personal PowerShell profile in all its glory

## Changes

In the past, I jammed everything I could into this profile. It was very long (approaching a 1000 lines), and starting to become very bloated. Because of the bloat, it was taking sometimes upto 45 SECONDS to load on low powered VMs. In addition, some of the items in my profile were very Windows specific, and while I manage alot of Windows boxes, my primary desktop at home and work are Linux-based, making these less important to me.

So, in the spirit of change (and probably a bit of best practices), I have moved about 500 lines from here into modules. Those modules are now in [Soarinferret/PowerShell](https://github.com/Soarinferret/PowerShell). My intention is start populating modules and scripts in that repo, and most likely eventually retire this repository. I also intend to start publishing some of my modules to the PowerShell Gallery at some point, but I definitely need to clean those up first, and add proper tests.