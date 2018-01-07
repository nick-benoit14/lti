# LTI


## About
This is a rust library designed to facilitate building LTI applications. LTI
prescribes a way to integrate rich learning applications (often remotely hosted
and provided through third-party services) with platforms like learning
management systems (LMS), portals, learning object repositories or other
educational environments managed locally or in the cloud. More info about the
LTI standard can be found
[here](https://www.imsglobal.org/activity/learning-tools-interoperability)

## Installation

Add `lti = "0.2.0"` to your Cargo.toml file

## Usage

The primary use case of LTI is to verify an lti launch. This ensures
that the request to your application has not been tampered with and
allows you to trust the given POST parameters.

Example of verifying an lti launch:

```rust
extern crate lti;

let valid_launch: bool = lti::verify_lti_launch(
  // HTTP Method (for lti launches this should be a post)
  "POST",

  // Full Uri for the lti launch
  "https://my_domain/lti_launch",

  // Url encoded request parameters
  my_www_form_urlencoded_params,

  // Consumer secret shared between Tool Consumer and Tool Provider
  my_consumer_secret
)
```

## Contributors

Portions of this code, in particular, the code that signs oauth requests was
heavily influenced, or taken from
[oauth-client-rs](https://github.com/gifnksm/oauth-client-rs). I hope to be
able to contribute back to that project upon hearing back from the project
owner.


