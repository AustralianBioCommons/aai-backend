# Changelog

## [1.1.0](https://github.com/AustralianBioCommons/aai-backend/compare/v1.0.0...v1.1.0) (2025-10-21)


### Features

* add admin route for capturing revoke reasonings ([e21d4fd](https://github.com/AustralianBioCommons/aai-backend/commit/e21d4fd84ec0346bc4ac83801e093cfa755ccf35))
* add allowed email domains for SBP registration to settings ([775fefd](https://github.com/AustralianBioCommons/aai-backend/commit/775fefd744f8e870111dea7f586f4743e3a48f06))
* Add extra information to the GET /users response for admin user list ([004a80d](https://github.com/AustralianBioCommons/aai-backend/commit/004a80d5fb473e70ac1da347b351a28826918316))
* add filters to /admin/users endpoint and allow combining multiple filters AAI-420 ([#86](https://github.com/AustralianBioCommons/aai-backend/issues/86)) ([1eb5993](https://github.com/AustralianBioCommons/aai-backend/commit/1eb59935dcaddf585a67c7e10410e94d8b92fe82))
* add short_name field to BiocommonsGroup and related models ([4c36dc7](https://github.com/AustralianBioCommons/aai-backend/commit/4c36dc74c617eeda5e57d0a745dafdfa761fefea))
* add version to GET / ([0c4df2f](https://github.com/AustralianBioCommons/aai-backend/commit/0c4df2f41656224eab755f2eec16380e51d2b129))
* add version to GET / ([bd46361](https://github.com/AustralianBioCommons/aai-backend/commit/bd46361c9c9976f0dfac7e2ab87d978e9b0250ea))
* db migration ([ac14193](https://github.com/AustralianBioCommons/aai-backend/commit/ac1419385a54265f4e9ec643d38ff68b063a7ea8))
* enable revoke access via updating db ([f3898ce](https://github.com/AustralianBioCommons/aai-backend/commit/f3898ced910767f9d0f68b380196893d1c20c5f1))
* enhance email domain validation for SBP registration with improved error handling and testing ([e091a19](https://github.com/AustralianBioCommons/aai-backend/commit/e091a195b62a85c28c247e081ab99ae63ee9f1c0))
* group and role sync to initialize/populate the backend database (AAI-452) ([#95](https://github.com/AustralianBioCommons/aai-backend/issues/95)) ([e884e14](https://github.com/AustralianBioCommons/aai-backend/commit/e884e14bc8f398de24bbe2867236f5c37a2fb7f9))
* implement email domain validation for SBP registration ([6f762bb](https://github.com/AustralianBioCommons/aai-backend/commit/6f762bb6f07df81e96fdc3c28f860800fae57d73))
* seperate approve / revoke in platforms and groups ([5a18831](https://github.com/AustralianBioCommons/aai-backend/commit/5a18831e00a9f32fe5f9e7e84fa34cdccef5abe0))
* soft-deletion of database objects ([#102](https://github.com/AustralianBioCommons/aai-backend/issues/102)) ([7b79d23](https://github.com/AustralianBioCommons/aai-backend/commit/7b79d23727f5026dfa19be05e5dff0473c0285e5))
* sync all master data ([#107](https://github.com/AustralianBioCommons/aai-backend/issues/107)) ([a314624](https://github.com/AustralianBioCommons/aai-backend/commit/a3146240fdcda736917a1dd28fb0262c3257b97b))
* update allowed email domains for SBP registration in .env.example ([20494d2](https://github.com/AustralianBioCommons/aai-backend/commit/20494d29e8a991e080e9c5f1c97e09ea3a942816))
* update allowed email domains for SBP registration in config and .env.example ([19b8b52](https://github.com/AustralianBioCommons/aai-backend/commit/19b8b5286278b235220fa10baf62921370a15f65))


### Bug Fixes

* add missing migration script ([2b079e9](https://github.com/AustralianBioCommons/aai-backend/commit/2b079e92fc3932c2eca1827913c219a73a35cb5b))
* add timeouts to DB connections to prevent DB lockout ([#104](https://github.com/AustralianBioCommons/aai-backend/issues/104)) ([0d07fc3](https://github.com/AustralianBioCommons/aai-backend/commit/0d07fc39525ed73df11b74bfd6bc71cdb501547a))
* admin routes and tests ([fd86c35](https://github.com/AustralianBioCommons/aai-backend/commit/fd86c35a09795f091e59119b4cb94138272adead))
* autodeploy ([27f7d73](https://github.com/AustralianBioCommons/aai-backend/commit/27f7d73a7fd37ae91a407bd20acfa87c051d3f66))
* autodeploy ([0ce3bd3](https://github.com/AustralianBioCommons/aai-backend/commit/0ce3bd3b69352c1512d4283999c895d5067aa00e))
* autodeploy ([6963672](https://github.com/AustralianBioCommons/aai-backend/commit/6963672a979e789994f06dc167dad6746cf96f3c))
* build and deploy ([1b43a40](https://github.com/AustralianBioCommons/aai-backend/commit/1b43a40f2912804e4240af6423c69cf75701b6a9))
* check admin roles for approval/revoke access ([f966774](https://github.com/AustralianBioCommons/aai-backend/commit/f9667744f488576eb595227a212981757fa4c7c0))
* dev version id PEP440 compliancy ([caba34b](https://github.com/AustralianBioCommons/aai-backend/commit/caba34b9ad14d07e452a9ce6dc4cc6dfc2e50a91))
* dev version id PEP440 compliancy ([d62c655](https://github.com/AustralianBioCommons/aai-backend/commit/d62c655817b7a5921fac263d7c08029d433fcf90))
* dev version id PEP440 compliancy ([28da907](https://github.com/AustralianBioCommons/aai-backend/commit/28da90767738e5f6842deb4e91f73cdfc1d18543))
* dev version id PEP440 compliancy ([c4484d7](https://github.com/AustralianBioCommons/aai-backend/commit/c4484d73f018c7b3aa2af8abd2a47fc2a7c8a79a))
* do not cause multiple migrations by limiting retry ([907d15b](https://github.com/AustralianBioCommons/aai-backend/commit/907d15bdd3dc88901522ffc9ab5cd057b41dedc8))
* don't use group or platform mapping ([9d9218c](https://github.com/AustralianBioCommons/aai-backend/commit/9d9218caf3f391192f0e06dd2118033ca854384a))
* duplicated instructions in README ([49f36c6](https://github.com/AustralianBioCommons/aai-backend/commit/49f36c6b42662c070b093986acc46bfba21f7474))
* fix db migration ([59e7707](https://github.com/AustralianBioCommons/aai-backend/commit/59e7707c05609b2c8cadcff063a43d1ea1da3aa6))
* fix db migration ([78bfc0d](https://github.com/AustralianBioCommons/aai-backend/commit/78bfc0d6f83bb6066681497c58c2e14a61f9fc5f))
* fix migrations, add a migration for revoke reason without deleting platform migrations ([bc54840](https://github.com/AustralianBioCommons/aai-backend/commit/bc548401134551b99e0ca262f860495d23fb6bb3))
* handle user stub on role sync ([#108](https://github.com/AustralianBioCommons/aai-backend/issues/108)) ([a5ba688](https://github.com/AustralianBioCommons/aai-backend/commit/a5ba688c2fdd8128dea7595c4157fa04f384a965))
* incorrect command for running the script ([afc8657](https://github.com/AustralianBioCommons/aai-backend/commit/afc8657ae4b693e3d1a36919863aa3bf9fcb8f8b))
* make pre-commit consistent with gh action ([186aca4](https://github.com/AustralianBioCommons/aai-backend/commit/186aca49b261f00123479d990b1d5cf2d3a03d97))
* make ruff happy ([8abd9be](https://github.com/AustralianBioCommons/aai-backend/commit/8abd9be204e39f78fd6ff785a1f0d4f8bc5581c8))
* make ruff happy ([0890d6b](https://github.com/AustralianBioCommons/aai-backend/commit/0890d6be15ff16a1be36c4d728816a72b99aa12c))
* migration files ([18c7a84](https://github.com/AustralianBioCommons/aai-backend/commit/18c7a84fb3d95c46525e68cf3c39a2653a017e62))
* migration files and lints ([2ed5011](https://github.com/AustralianBioCommons/aai-backend/commit/2ed5011c6e3952ee0ef9cd58b8c85d42d581a313))
* publish upon version tag, instead of published release ([59d0d2f](https://github.com/AustralianBioCommons/aai-backend/commit/59d0d2fd50cdada23c97f8c1681b797159aea9d9))
* remove obsolete Galaxy username check ([#105](https://github.com/AustralianBioCommons/aai-backend/issues/105)) ([4f28113](https://github.com/AustralianBioCommons/aai-backend/commit/4f28113d1ab8b4ca12cc558f0c70b9a6b2e89c52))
* remove unused resources and services routes ([ea637e9](https://github.com/AustralianBioCommons/aai-backend/commit/ea637e94b4bb6d2eb8d5212f125534ce21ecfee5))
* run schema generation with uv so required packages are installed ([7405a53](https://github.com/AustralianBioCommons/aai-backend/commit/7405a538ee59bbb9ae4a3200603c0eab2fefce75))
* run_scheduler.py --immediate on empty database causes exception ([#96](https://github.com/AustralianBioCommons/aai-backend/issues/96)) ([2790af0](https://github.com/AustralianBioCommons/aai-backend/commit/2790af0003a82796248221165762025f73fcdc2f))
* switch release please to python release type ([1023c4b](https://github.com/AustralianBioCommons/aai-backend/commit/1023c4b56b44d9a7ec18fc73a30270cc9f48ab1c))
* switch to python version string ([d844bc2](https://github.com/AustralianBioCommons/aai-backend/commit/d844bc29a26303f0354010b11988b87cb0e8d626))
* tests ([97fe40e](https://github.com/AustralianBioCommons/aai-backend/commit/97fe40e2a9d9dc5342d69f416a1e4d6cf65968b6))
* url to repo github secrets ([ecbde09](https://github.com/AustralianBioCommons/aai-backend/commit/ecbde092031f1eada06cbecbc8a390d8b0d21422))
* use migration task for migration ([d89fa08](https://github.com/AustralianBioCommons/aai-backend/commit/d89fa08754ea182f076e4f83d71178683a729e83))


### Documentation

* add missing Platform model in diagram ([dce9033](https://github.com/AustralianBioCommons/aai-backend/commit/dce9033cff4b2e2bbb96a8026131b97c36bbcac9))
* add more details for migration changes ([587329d](https://github.com/AustralianBioCommons/aai-backend/commit/587329d15ed9ee1723862eeb2e4a8ffff9ce8349))
* add reminder to update secrets ([28e2ff0](https://github.com/AustralianBioCommons/aai-backend/commit/28e2ff0f46d00b85dfa9f6ac9e987dbec5e69ab3))
* add reminder to update secrets ([db28c41](https://github.com/AustralianBioCommons/aai-backend/commit/db28c417fe6ff788bfd4876614d222675e08002e))
* add sample pull request for updating database schema diagram ([563da82](https://github.com/AustralianBioCommons/aai-backend/commit/563da825e36fd4c0cfd46f0fa7032638a81559c6))
* add sample pull request for updating database schema diagram ([d59f7ae](https://github.com/AustralianBioCommons/aai-backend/commit/d59f7ae41b5b69cc61a00f31dfcc715d5ec3200b))
* update database schema diagrams ([a674c5a](https://github.com/AustralianBioCommons/aai-backend/commit/a674c5a46a5e16aa44e740f249096341dbbc48e4))
* update database schema diagrams ([a44120b](https://github.com/AustralianBioCommons/aai-backend/commit/a44120b078c071a98538f3369bfe92f3498e69b1))

## 1.0.0 (2025-09-26)


### Features

* add Platform database model that defines the admin roles for each platform AAI-388 ([#80](https://github.com/AustralianBioCommons/aai-backend/issues/80)) ([e721d0e](https://github.com/AustralianBioCommons/aai-backend/commit/e721d0e44c5a1b221fb861a9d37f7e1162e3d0b5))


### Bug Fixes

* `get_users()` so it accepts a q filter ([ca1da5d](https://github.com/AustralianBioCommons/aai-backend/commit/ca1da5d87179bc46506d816fe2f635bc901954ee))
* get_users() so it accepts a q filter ([1da6a78](https://github.com/AustralianBioCommons/aai-backend/commit/1da6a7852922a18ce93f8a80d41e798b8d084f6f))
* set release-please type to simple ([bf63694](https://github.com/AustralianBioCommons/aai-backend/commit/bf6369446d780c90c80fede405471aff2c1a1b13))
* set release-please type to simple ([08b249b](https://github.com/AustralianBioCommons/aai-backend/commit/08b249b3f1e438b61dc0386099fd105b87781874))
