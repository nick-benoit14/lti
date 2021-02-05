//! This is a rust library designed to facilitate building LTI applications. LTI
//! prescribes a way to integrate rich learning applications (often remotely hosted
//! and provided through third-party services) with platforms like learning
//! management systems (LMS), portals, learning object repositories or other
//! educational environments managed locally or in the cloud. More info about the
//! LTI standard can be found
//! [here](https://www.imsglobal.org/activity/learning-tools-interoperability)
//!
//! ## Usage
//!
//! The primary use case of LTI is to verify an lti launch. This ensures
//! that the request to your application has not been tampered with and
//! allows you to trust the given POST parameters.
//!
//! Example of verifying an lti launch:
//!
//! ```rust
//!  extern crate lti;
//!  let my_www_form_urlencoded_params = "oauth_consumer_key=asdf...";
//!  let my_consumer_secret = "asdf";
//!  let valid_launch: bool = lti::verify_lti_launch(
//!    // HTTP Method (for lti launches this should be a post)
//!    "POST",
//!
//!    // Full Uri for the lti launch
//!    "https://my_domain/lti_launch",
//!
//!    // Url encoded request parameters
//!    my_www_form_urlencoded_params,
//!
//!    // Consumer secret shared between Tool Consumer and Tool Provider
//!    my_consumer_secret
//!  );
//! ```

use ring::hmac;
use url::percent_encoding;

// Percent encode string
fn encode(s: &str) -> String {
     percent_encoding::percent_encode(s.as_bytes(), StrictEncodeSet).collect()
}

#[derive(Copy, Clone)]
struct StrictEncodeSet;

// Encode all but the unreserved characters defined in
// RFC 3986, section 2.3. "Unreserved Characters"
// https://tools.ietf.org/html/rfc3986#page-12
//
// This is required by
// OAuth Core 1.0, section 5.1. "Parameter Encoding"
// https://oauth.net/core/1.0/#encoding_parameters
impl percent_encoding::EncodeSet for StrictEncodeSet {
    #[inline]
    fn contains(&self, byte: u8) -> bool {
        !((byte >= 0x61 && byte <= 0x7a) || // A-Z
          (byte >= 0x41 && byte <= 0x5a) || // a-z
          (byte >= 0x30 && byte <= 0x39) || // 0-9
          (byte == 0x2d) || // -
          (byte == 0x2e) || // .
          (byte == 0x5f) || // _
          (byte == 0x7e)) // ~
    }
}


fn parse_launch_params(params: &str) -> Vec<(String, String)>{
   serde_urlencoded::from_str::<Vec<(String, String)>>(params).unwrap()
}

fn find_oauth_signature_index(parsed_launch_params: &Vec<(String, String)>)-> Option<usize>{
  parsed_launch_params.iter().position(|e| e.0 == "oauth_signature")
}

fn signed_launch_params(parsed_launch_params: &mut Vec<(String, String)>) -> String{
    let index = find_oauth_signature_index(parsed_launch_params);

    // Remove oauth_signature if it was provided
    if let Some(i) = index {
       parsed_launch_params.remove(i);
    }

    parsed_launch_params.sort_by_key(|a| a.clone().0);
    let mut encoded = Vec::new();
    for v in parsed_launch_params{
      encoded.push(format!("{}={}",encode(&v.0[..]),encode(&v.1[..])));
    }

    encoded.join("&")
}

fn request_signature(parsed_launch_params: &Vec<(String, String)>) -> Option<String>{
    match find_oauth_signature_index(parsed_launch_params) {
      Some(x) => { Some(parsed_launch_params[x].1.clone()) },
      None => { None }
    }
}

/// Generates the signature for a given LTI launch.
///
/// Standard details can be found [here](http://www.imsglobal.org/specs/ltiv1p0/implementation-guide#toc-4)
///
/// method - The HTTP method of the request, generally either GET or POST
///
/// uri - The destination uri of the lti launch request. This will generally
/// be the uri of the tool provider lti launch route.
///
/// params - The stringified lti_launch parameters. This includes query paramters
/// for a GET request, and form encoded parameters for a POST request. Details
/// can be found [here](https://oauth1.wp-api.org/docs/basics/Signing.html)
///
/// consumer_secret - The shared secret for the given Tool Consumer
///
/// token_secret - Generally not used for lti launch requests. Details can
/// be found [here](https://oauth1.wp-api.org/docs/basics/Signing.html)
pub fn signature(
             method: &str,
             uri: &str,
             params: &str,
             consumer_secret: &str,
             token_secret: Option<&str>)
             -> String {
    let base = format!("{}&{}&{}", encode(method), encode(uri), encode(&params));
    let key = format!("{}&{}",
                      encode(consumer_secret),
                      encode(token_secret.unwrap_or("")));
    let signing_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_bytes());
    let signature = hmac::sign(&signing_key, base.as_bytes());
    base64::encode(signature.as_ref())
}

/// Verify a given lti launch
///
/// Lti Launch verification essentially entails duplicating the
/// process that the Tool Consumer used to produce the oauth_signature,
/// then verifying the signatures match. This ensures that no data has
/// been altered since the Tool Consumer signed the request.
///
/// # Example
///
/// ```rust
///  extern crate lti;
///  let my_www_form_urlencoded_params = "oauth_consumer_key=asdf...";
///  let my_consumer_secret = "asdf";
///  let valid_launch: bool = lti::verify_lti_launch(
///    // HTTP Method (for lti launches this should be a post)
///    "POST",
///
///    // Full Uri for the lti launch
///    "https://my_domain/lti_launch",
///
///    // Url encoded request parameters
///    my_www_form_urlencoded_params,
///
///    // Consumer secret shared between Tool Consumer and Tool Provider
///    my_consumer_secret
///  );

/// ```
///
/// method - The HTTP method of the request, generally either GET or POST
///
/// uri - The destination uri of the lti launch request. This will generally
/// be the uri of the tool provider lti launch route.
///
/// params - The stringified lti_launch parameters. This includes query paramters
/// for a GET request, and form encoded parameters for a POST request. Details
/// can be found [here](https://oauth1.wp-api.org/docs/basics/Signing.html)
///
/// consumer_secret - The shared secret for the given Tool Consumer
pub fn verify_lti_launch(method: &str, uri: &str, params: &str,
                        consumer_secret: &str) -> bool{
    let parsed_params = parse_launch_params(params);
    let signed_params = signed_launch_params(&mut parsed_params.clone());
    let generated_signature = signature(method, uri, &signed_params, consumer_secret, None);

    let given_request_signature = request_signature(&parsed_params);
    match given_request_signature {
      Some(request_signature) => generated_signature == request_signature,
      None => false
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::verify_lti_launch;

    const METHOD: &str =  "POST";
    const URL: &str = "https://localhost:8000/lti_launch";
    const LAUNCH_PARAMS: &str = "oauth_consumer_key=asdf&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1514046098&oauth_nonce=SsBR2Ml1DGJifxebOZdc599WcAVqoL2OMdaU3dF2QAo&oauth_version=1.0&context_id=a1c750eae5b6201fa5acf2265bc46bf24e9a2d1c&context_label=Nick+3&context_title=Nick+Test+Course+3&custom_canvas_enrollment_state=active&ext_roles=urn%3Alti%3Ainstrole%3Aims%2Flis%2FAdministrator%2Curn%3Alti%3Ainstrole%3Aims%2Flis%2FInstructor%2Curn%3Alti%3Arole%3Aims%2Flis%2FInstructor%2Curn%3Alti%3Asysrole%3Aims%2Flis%2FUser&launch_presentation_document_target=iframe&launch_presentation_height=400&launch_presentation_locale=en&launch_presentation_return_url=https%3A%2F%2Fatomicjolt.instructure.com%2Fcourses%2F1773%2Fexternal_content%2Fsuccess%2Fexternal_tool_redirect&launch_presentation_width=800&lti_message_type=basic-lti-launch-request&lti_version=LTI-1p0&oauth_callback=about%3Ablank&resource_link_id=a1c750eae5b6201fa5acf2265bc46bf24e9a2d1c&resource_link_title=Rust+Lti&roles=Instructor%2Curn%3Alti%3Ainstrole%3Aims%2Flis%2FAdministrator&tool_consumer_info_product_family_code=canvas&tool_consumer_info_version=cloud&tool_consumer_instance_contact_email=notifications%40instructure.com&tool_consumer_instance_guid=4MRcxnx6vQbFXxhLb8005m5WXFM2Z2i8lQwhJ1QT%3Acanvas-lms&tool_consumer_instance_name=Atomic+Jolt&user_id=a9b06584c017eeb049ef6010f48120f0e91b39dd&oauth_signature=HbEIQOtSTK942Z5bnSkHC0FjSLs%3D";
    const CONSUMER_SECRET: &str = "asdf";
    const INVALID_SECRET: &str = "asdfasdf";

    /// Test that a valid lti launch passes
    ///
    /// These results were obtained from setting
    /// up an lti launch in Instructure's Canvas LMS
    /// more details can be found here: https://github.com/instructure/canvas-lms
    #[test]
    fn it_verifies_correct_signature() {
        let result = verify_lti_launch(
            METHOD,
            URL,
            LAUNCH_PARAMS,
            CONSUMER_SECRET,
            );
        assert_eq!(result, true);
    }

    /// Test that invalid launch is not verified
   #[test]
   fn it_does_not_verify_incorrect_signatur() {
        let result = verify_lti_launch(
            METHOD,
            URL,
            LAUNCH_PARAMS,
            INVALID_SECRET,
            );
        assert_eq!(result, false);
   }
}
