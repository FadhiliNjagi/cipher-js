2.1.0-0
===
* Add support for keys with encoding prefix e.g. `base64:P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc=`
* Remove buffer-from dependency

2.0.0
===
* Test integration with other libraries. So far so good.

2.0.0-dev
===
* Add `decodeKey(key, keyEncoding)`
* Change cipher encoding format from hex to base64, to create shorter strings
* deps: buffer-from@1.1.2
  - Add compatibility with older node versions (>= 0.10) for `Buffer.from`
* Remove esm distribution. Library is now purely commonJS (es5)
* More thorough tests

1.0.0
===
* Stable API
* Cookie encryption and decryption
* Security guidelines for encryption keys


0.1.0 (deleted)
===
* Unstable API
* README typos