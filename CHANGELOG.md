# Changelog

## [1.1.0](https://github.com/AustralianBioCommons/aai-backend/compare/v1.0.0...v1.1.0) (2025-10-03)


### Features

* add admin route for capturing revoke reasonings ([e21d4fd](https://github.com/AustralianBioCommons/aai-backend/commit/e21d4fd84ec0346bc4ac83801e093cfa755ccf35))
* add allowed email domains for SBP registration to settings ([775fefd](https://github.com/AustralianBioCommons/aai-backend/commit/775fefd744f8e870111dea7f586f4743e3a48f06))
* add filters to /admin/users endpoint and allow combining multiple filters AAI-420 ([#86](https://github.com/AustralianBioCommons/aai-backend/issues/86)) ([1eb5993](https://github.com/AustralianBioCommons/aai-backend/commit/1eb59935dcaddf585a67c7e10410e94d8b92fe82))
* add version to GET / ([0c4df2f](https://github.com/AustralianBioCommons/aai-backend/commit/0c4df2f41656224eab755f2eec16380e51d2b129))
* add version to GET / ([bd46361](https://github.com/AustralianBioCommons/aai-backend/commit/bd46361c9c9976f0dfac7e2ab87d978e9b0250ea))
* enable revoke access via updating db ([f3898ce](https://github.com/AustralianBioCommons/aai-backend/commit/f3898ced910767f9d0f68b380196893d1c20c5f1))
* enhance email domain validation for SBP registration with improved error handling and testing ([e091a19](https://github.com/AustralianBioCommons/aai-backend/commit/e091a195b62a85c28c247e081ab99ae63ee9f1c0))
* implement email domain validation for SBP registration ([6f762bb](https://github.com/AustralianBioCommons/aai-backend/commit/6f762bb6f07df81e96fdc3c28f860800fae57d73))
* seperate approve / revoke in platforms and groups ([5a18831](https://github.com/AustralianBioCommons/aai-backend/commit/5a18831e00a9f32fe5f9e7e84fa34cdccef5abe0))
* update allowed email domains for SBP registration in .env.example ([20494d2](https://github.com/AustralianBioCommons/aai-backend/commit/20494d29e8a991e080e9c5f1c97e09ea3a942816))
* update allowed email domains for SBP registration in config and .env.example ([19b8b52](https://github.com/AustralianBioCommons/aai-backend/commit/19b8b5286278b235220fa10baf62921370a15f65))


### Bug Fixes

* add missing migration script ([2b079e9](https://github.com/AustralianBioCommons/aai-backend/commit/2b079e92fc3932c2eca1827913c219a73a35cb5b))
* admin routes and tests ([fd86c35](https://github.com/AustralianBioCommons/aai-backend/commit/fd86c35a09795f091e59119b4cb94138272adead))
* autodeploy ([27f7d73](https://github.com/AustralianBioCommons/aai-backend/commit/27f7d73a7fd37ae91a407bd20acfa87c051d3f66))
* autodeploy ([0ce3bd3](https://github.com/AustralianBioCommons/aai-backend/commit/0ce3bd3b69352c1512d4283999c895d5067aa00e))
* autodeploy ([6963672](https://github.com/AustralianBioCommons/aai-backend/commit/6963672a979e789994f06dc167dad6746cf96f3c))
* build and deploy ([1b43a40](https://github.com/AustralianBioCommons/aai-backend/commit/1b43a40f2912804e4240af6423c69cf75701b6a9))
* check admin roles for approval/revoke access ([f966774](https://github.com/AustralianBioCommons/aai-backend/commit/f9667744f488576eb595227a212981757fa4c7c0))
* don't use group or platform mapping ([9d9218c](https://github.com/AustralianBioCommons/aai-backend/commit/9d9218caf3f391192f0e06dd2118033ca854384a))
* duplicated instructions in README ([49f36c6](https://github.com/AustralianBioCommons/aai-backend/commit/49f36c6b42662c070b093986acc46bfba21f7474))
* fix migrations, add a migration for revoke reason without deleting platform migrations ([bc54840](https://github.com/AustralianBioCommons/aai-backend/commit/bc548401134551b99e0ca262f860495d23fb6bb3))
* incorrect command for running the script ([afc8657](https://github.com/AustralianBioCommons/aai-backend/commit/afc8657ae4b693e3d1a36919863aa3bf9fcb8f8b))
* make pre-commit consistent with gh action ([186aca4](https://github.com/AustralianBioCommons/aai-backend/commit/186aca49b261f00123479d990b1d5cf2d3a03d97))
* make ruff happy ([8abd9be](https://github.com/AustralianBioCommons/aai-backend/commit/8abd9be204e39f78fd6ff785a1f0d4f8bc5581c8))
* make ruff happy ([0890d6b](https://github.com/AustralianBioCommons/aai-backend/commit/0890d6be15ff16a1be36c4d728816a72b99aa12c))
* migration files ([18c7a84](https://github.com/AustralianBioCommons/aai-backend/commit/18c7a84fb3d95c46525e68cf3c39a2653a017e62))
* migration files and lints ([2ed5011](https://github.com/AustralianBioCommons/aai-backend/commit/2ed5011c6e3952ee0ef9cd58b8c85d42d581a313))
* publish upon version tag, instead of published release ([59d0d2f](https://github.com/AustralianBioCommons/aai-backend/commit/59d0d2fd50cdada23c97f8c1681b797159aea9d9))
* remove unused resources and services routes ([ea637e9](https://github.com/AustralianBioCommons/aai-backend/commit/ea637e94b4bb6d2eb8d5212f125534ce21ecfee5))
* run schema generation with uv so required packages are installed ([7405a53](https://github.com/AustralianBioCommons/aai-backend/commit/7405a538ee59bbb9ae4a3200603c0eab2fefce75))
* tests ([97fe40e](https://github.com/AustralianBioCommons/aai-backend/commit/97fe40e2a9d9dc5342d69f416a1e4d6cf65968b6))
* url to repo github secrets ([ecbde09](https://github.com/AustralianBioCommons/aai-backend/commit/ecbde092031f1eada06cbecbc8a390d8b0d21422))
* use migration task for migration ([d89fa08](https://github.com/AustralianBioCommons/aai-backend/commit/d89fa08754ea182f076e4f83d71178683a729e83))

## 1.0.0 (2025-09-26)


### Features

* add Platform database model that defines the admin roles for each platform AAI-388 ([#80](https://github.com/AustralianBioCommons/aai-backend/issues/80)) ([e721d0e](https://github.com/AustralianBioCommons/aai-backend/commit/e721d0e44c5a1b221fb861a9d37f7e1162e3d0b5))


### Bug Fixes

* `get_users()` so it accepts a q filter ([ca1da5d](https://github.com/AustralianBioCommons/aai-backend/commit/ca1da5d87179bc46506d816fe2f635bc901954ee))
* get_users() so it accepts a q filter ([1da6a78](https://github.com/AustralianBioCommons/aai-backend/commit/1da6a7852922a18ce93f8a80d41e798b8d084f6f))
* set release-please type to simple ([bf63694](https://github.com/AustralianBioCommons/aai-backend/commit/bf6369446d780c90c80fede405471aff2c1a1b13))
* set release-please type to simple ([08b249b](https://github.com/AustralianBioCommons/aai-backend/commit/08b249b3f1e438b61dc0386099fd105b87781874))
