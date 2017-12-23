extern crate url;
extern crate base64;
extern crate ring;
extern crate serde_urlencoded;
use ring::digest;
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

fn signed_launch_params(params: &str) -> String{
    let mut result = serde_urlencoded::from_str::<Vec<(String, String)>>(&params[..]).unwrap();
    result.pop(); //TODO ensure we actually remove signature
    result.sort_by_key(|a| a.clone().0);
    let mut encoded = Vec::new();
    for v in &result{
      encoded.push(format!("{}={}",encode(&v.0[..]),encode(&v.1[..])));
    }

    encoded.join("&")
}

pub fn signature(method: &str,
              uri: &str,
             params: &str,
             consumer_secret: &str,
             token_secret: Option<&str>)
             -> String {
    let signed_params = signed_launch_params(params);

    let base = format!("{}&{}&{}", encode(method), encode(uri), encode(&signed_params));
    let key = format!("{}&{}",
                      encode(consumer_secret),
                      encode(token_secret.unwrap_or("")));

    let signing_key = hmac::SigningKey::new(&digest::SHA1, key.as_bytes());
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
///```rust
///  extern crate lti;
///
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
///    my_consumer_secret,
///
///    // Signature provided by Tool Consumer. This should be
///    // provided in the post parameters as 'oauth_signature'
///    provided_signature,
///  )
///
/// ```
pub fn verify_lti_launch(method: &str, uri: &str, query: &str,
                        consumer_secret: &str,request_signature: &str) -> bool{
    let sig = signature(method, uri, query, consumer_secret, None);
    sig == request_signature
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
    const EXPECTED_SIGNATURE: &str = "HbEIQOtSTK942Z5bnSkHC0FjSLs=";

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
            EXPECTED_SIGNATURE
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
            EXPECTED_SIGNATURE
            );
        assert_eq!(result, false);
   }
}
