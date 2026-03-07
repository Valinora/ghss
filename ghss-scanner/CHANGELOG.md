# Changelog

## [0.4.0](https://github.com/Valinora/ghss/compare/v0.3.0...v0.4.0) (2026-03-07)


### Features

* **ci:** add CI/CD pipeline with SHA-pinned actions, release-please, and Renovate ([ec4a455](https://github.com/Valinora/ghss/commit/ec4a455e8b19d9edbdbc49572646840456ffa6e7))
* **ci:** add release workflow ([2359555](https://github.com/Valinora/ghss/commit/235955547b43d016d82203726b9c082ded4f69da))
* **scanner:** add config parsing, CLI bootstrap, and validation ([1ec9e8c](https://github.com/Valinora/ghss/commit/1ec9e8c49278ba5fe6f127d9b6591bd1771b3816))
* **scanner:** add cron scheduling and dummy scan loop ([96a6b10](https://github.com/Valinora/ghss/commit/96a6b10b17c2c44f72cec9592a4567852cf89d16))
* **scanner:** add graceful shutdown and end-to-end integration tests ([0cd8ca4](https://github.com/Valinora/ghss/commit/0cd8ca452eeb645bbea2f3bfa711b1c91818c845))
* **scanner:** add per-finding status markers and demo script ([01ebc0f](https://github.com/Valinora/ghss/commit/01ebc0f8795c62f2e3e2548129aff1cd4ee6be23))
* **scanner:** add SQLite persistence with migrations and drift detection ([99e03c8](https://github.com/Valinora/ghss/commit/99e03c82ae5f355192e860dbf9205d5f12265b4b))
* **scanner:** wire up the scanner to actually scan things ([#13](https://github.com/Valinora/ghss/issues/13)) ([9f5ca50](https://github.com/Valinora/ghss/commit/9f5ca50cc34a83bdf94e1b2bbff9d1d26b486d64))


### Bug Fixes

* **ci:** resolve clippy and cargo-audit failures ([#4](https://github.com/Valinora/ghss/issues/4)) ([2e79f1e](https://github.com/Valinora/ghss/commit/2e79f1ea9fd01f6997dbb93d521f49d2d14b42c0))

## [0.3.0](https://github.com/Valinora/ghss/compare/v0.2.0...v0.3.0) (2026-03-05)


### Features

* **ci:** add CI/CD pipeline with SHA-pinned actions, release-please, and Renovate ([ec4a455](https://github.com/Valinora/ghss/commit/ec4a455e8b19d9edbdbc49572646840456ffa6e7))
* **ci:** add release workflow ([2359555](https://github.com/Valinora/ghss/commit/235955547b43d016d82203726b9c082ded4f69da))
* **scanner:** add config parsing, CLI bootstrap, and validation ([1ec9e8c](https://github.com/Valinora/ghss/commit/1ec9e8c49278ba5fe6f127d9b6591bd1771b3816))
* **scanner:** add cron scheduling and dummy scan loop ([96a6b10](https://github.com/Valinora/ghss/commit/96a6b10b17c2c44f72cec9592a4567852cf89d16))
* **scanner:** add graceful shutdown and end-to-end integration tests ([0cd8ca4](https://github.com/Valinora/ghss/commit/0cd8ca452eeb645bbea2f3bfa711b1c91818c845))
* **scanner:** add per-finding status markers and demo script ([01ebc0f](https://github.com/Valinora/ghss/commit/01ebc0f8795c62f2e3e2548129aff1cd4ee6be23))
* **scanner:** add SQLite persistence with migrations and drift detection ([99e03c8](https://github.com/Valinora/ghss/commit/99e03c82ae5f355192e860dbf9205d5f12265b4b))
* **scanner:** wire up the scanner to actually scan things ([#13](https://github.com/Valinora/ghss/issues/13)) ([9f5ca50](https://github.com/Valinora/ghss/commit/9f5ca50cc34a83bdf94e1b2bbff9d1d26b486d64))


### Bug Fixes

* **ci:** resolve clippy and cargo-audit failures ([#4](https://github.com/Valinora/ghss/issues/4)) ([2e79f1e](https://github.com/Valinora/ghss/commit/2e79f1ea9fd01f6997dbb93d521f49d2d14b42c0))

## [0.2.0](https://github.com/Valinora/ghss/compare/v0.1.0...v0.2.0) (2026-03-05)


### Features

* **scanner:** wire up the scanner to actually scan things ([#13](https://github.com/Valinora/ghss/issues/13)) ([9f5ca50](https://github.com/Valinora/ghss/commit/9f5ca50cc34a83bdf94e1b2bbff9d1d26b486d64))


### Bug Fixes

* **ci:** resolve clippy and cargo-audit failures ([#4](https://github.com/Valinora/ghss/issues/4)) ([2e79f1e](https://github.com/Valinora/ghss/commit/2e79f1ea9fd01f6997dbb93d521f49d2d14b42c0))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * ghss bumped from 0.1.0 to 0.1.1

## 0.1.0 (2026-03-04)


### Features

* **ci:** add CI/CD pipeline with SHA-pinned actions, release-please, and Renovate ([ec4a455](https://github.com/Valinora/ghss/commit/ec4a455e8b19d9edbdbc49572646840456ffa6e7))
* **ci:** add release workflow ([2359555](https://github.com/Valinora/ghss/commit/235955547b43d016d82203726b9c082ded4f69da))
* **scanner:** add config parsing, CLI bootstrap, and validation ([1ec9e8c](https://github.com/Valinora/ghss/commit/1ec9e8c49278ba5fe6f127d9b6591bd1771b3816))
* **scanner:** add cron scheduling and dummy scan loop ([96a6b10](https://github.com/Valinora/ghss/commit/96a6b10b17c2c44f72cec9592a4567852cf89d16))
* **scanner:** add graceful shutdown and end-to-end integration tests ([0cd8ca4](https://github.com/Valinora/ghss/commit/0cd8ca452eeb645bbea2f3bfa711b1c91818c845))
* **scanner:** add per-finding status markers and demo script ([01ebc0f](https://github.com/Valinora/ghss/commit/01ebc0f8795c62f2e3e2548129aff1cd4ee6be23))
* **scanner:** add SQLite persistence with migrations and drift detection ([99e03c8](https://github.com/Valinora/ghss/commit/99e03c82ae5f355192e860dbf9205d5f12265b4b))
