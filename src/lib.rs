use std::collections::HashSet;

use scraper::{Html, Selector};
use sha2::{Sha384, Digest};
use base64::{Engine, engine::{general_purpose}};

/// Hashes inline <script> elements using SHA384. Returns an error if input is not a valid HTML document.
pub fn csp_hashes_from_html_document(
    html: &str,
) -> Result<HashSet<String>, String> {
    let doc = Html::parse_document(html);
    let script = Selector::parse("script").expect("could not instantiate script selector");
    let hashes = doc.select(&script).map(|s| {
        let mut hasher = Sha384::new();
        hasher.update(s.inner_html().as_bytes());
        let hash = hasher.finalize();
        let b64 = general_purpose::STANDARD.encode(hash);
        format!("sha384-{b64}")
    })
    .collect::<HashSet<String>>();

    if let Some(error) =  doc.errors.first() {
        Err(error.to_string())
    } else {
        Ok(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_html_no_scripts() {
        assert!(
            csp_hashes_from_html_document(
                r#"<!doctype html><title>a</title>"#
            ).unwrap().is_empty()
        );
    }

    #[test]
    fn valid_html_with_scripts() {
        assert_eq!(
            csp_hashes_from_html_document(
                r#"<!doctype html>
                <html>
                    <head>
                        <title>woof</title>
                        <script>console.log("in head")</script>
                    </head>
                    <body>
                        <script>console.log("in body")</script>
                    </body>
                </html>"#
            ).unwrap(),
            HashSet::from_iter(vec![
                "sha384-DSCsjoY4lRFgW2ltWTCEhMG+WSglTblYcvUcCd/X4ua88hLymWLjdMdNAEXJF1R9".to_string(),
                "sha384-8wiu0e3/t6a55K7REGqooaRsccJwaR4CH2UgjuPia5OjmnWavbRbuAk4NL+WJ07o".to_string()
            ])
        );
    }

    #[test]
    fn invalid_html_errors() {
        assert!(
            csp_hashes_from_html_document(
                r#"<!doctype html>
                <html>
                    <head
                        <script>console.log("in head")</script>
                    </head>
                    <body>
                        <script>console.log("in body")</script>
                    </body>
                </html>"#
            ).is_err()
        );
    }

    #[test]
    fn html_fragment_errors() {
        assert!(
            csp_hashes_from_html_document(
                r#"<body>
                        <script>console.log("in body")</script>
                    </body>"#
            ).is_err()
        );
    }
}
