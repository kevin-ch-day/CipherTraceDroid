# Chrome lifecycle evidence

Android lifecycle history recorded Chrome resumed at local device time `23:15:12`, after PCAPdroid activation and before the attempted device-control gate. It then cycled through paused/stopped/resumed states and finally paused/stopped after the abort request.

This establishes that the control precondition failed independently of packet contents.
