# <img src="images/icon.png" align="center"> Win-User-Pref

> Rust Library for Reading/Writing a handful of per-user Preferences on Windows

## Purpose

Many of the users for my chrome extension [Chrometana Pro](https://github.com/MarcGuiselin/chrometana-pro) were complaining about the installation process for [EdgeDeflector](https://github.com/da2x/EdgeDeflector) not working on their machines. For that reason I developed an alternative application called [Wedge](https://github.com/MarcGuiselin/wedge) installed via a home-made installer. After confirming with the user the installer configures their system automatically to deflect edge links to their default browser.

This library was developed for [the Wedge installer](https://github.com/MarcGuiselin/wedge/tree/master/crates/installer) and a future project I am working on. This code is released for transparency. Altering system settings is a bit of a grey area, so __I don't recommend using this library__ unless you know what you are doing.

## License and Copyright

This code is currently __not licensed__. This might change in the future. Contact me if you want permission to use it: [marc@guiselin.com](mailto:marc@guiselin.com).

 - Permissively licensed for [Wedge](https://github.com/MarcGuiselin/wedge)