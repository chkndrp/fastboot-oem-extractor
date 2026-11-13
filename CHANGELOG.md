# 2.0.0
- Breaking change: renamed `-fsl` (force string lookup) CLI argument to `-f`
- Added a proper input validation to public functions to prevent silent errors
- Added `--output` CLI argument for saving the clean output to a file
- Added `--offset` CLI & library argument for reading the bootloader image at an offset
- Added dependabot configuration
- Fixed broken quick start example in `README.md`
- Fixed a bug/derp that caused the UEFI parser to read only 200Kb and not 10Mb
- Made pylint dev dependency locked to 4.x major version

# 1.1.0
- Added is_raw_image() function 
- Added `py.typed` typing hint for IDEs
- Added more keywords to pyproject.toml
- Restructured and improved README

# 1.0.3
- Added support for legacy MTK magic bytes
- Added support for FDT/DTB/FIT magic bytes
- Moved pylint configuration to pyproject.toml, fixed license field
- Fixed a typo in the README

# 1.0.2
- Initial PyPi release

# 1.0.1 - 1.0.0
- Issues with PyPi, ignore this
