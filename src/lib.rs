use std::collections::HashSet;

use base64::{engine::general_purpose, Engine};
use scraper::{Html, Selector};
use sha2::{Digest, Sha256};

/// Hashes inline <script> and <style> elements using SHA256. Returns an error if input is not a valid HTML document.
pub fn csp_hashes_from_html_document(html: &str) -> Result<HashSet<String>, String> {
    let doc = Html::parse_document(html);

    // script elements
    let script = Selector::parse("script").expect("could not instantiate script selector");
    let mut hashes = doc
        .select(&script)
        .map(|s| {
            let mut hasher = Sha256::new();
            hasher.update(s.inner_html().as_bytes());
            let hash = hasher.finalize();
            let b64 = general_purpose::STANDARD.encode(hash);
            format!("sha256-{b64}")
        })
        .collect::<HashSet<String>>();

    // style elements
    let style = Selector::parse("style").expect("could not instantiate script selector");
    hashes.extend(doc.select(&style).map(|s| {
        let mut hasher = Sha256::new();
        hasher.update(s.inner_html().as_bytes());
        let hash = hasher.finalize();
        let b64 = general_purpose::STANDARD.encode(hash);
        format!("sha256-{b64}")
    }));

    if let Some(error) = doc.errors.first() {
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
            csp_hashes_from_html_document(r#"<!doctype html><title>a</title>"#)
                .unwrap()
                .is_empty()
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
            )
            .unwrap(),
            HashSet::from_iter(vec![
                "sha256-vjwjwnBndhWG+ZN6vpRKSmbicObZIQarx7RgSb3DmA8=".to_string(),
                "sha256-3oUpClVK/cNQB5x9TStM+xLiHETuIGGp2vGZRQdvHX0=".to_string()
            ])
        );
    }

    #[test]
    fn invalid_html_errors() {
        assert!(csp_hashes_from_html_document(
            r#"<!doctype html>
                <html>
                    <head
                        <script>console.log("in head")</script>
                    </head>
                    <body>
                        <script>console.log("in body")</script>
                    </body>
                </html>"#
        )
        .is_err());
    }

    #[test]
    fn html_fragment_errors() {
        assert!(csp_hashes_from_html_document(
            r#"<body>
                        <script>console.log("in body")</script>
                    </body>"#
        )
        .is_err());
    }

    #[test]
    fn valid_html_with_style() {
        assert_eq!(
            csp_hashes_from_html_document(
                r#"<!doctype html>
                <html>
                    <head>
                        <title>woof</title>
                        <style>
                            body {
                                font-family: cursive;
                            }
                        </style>
                    </head>
                    <body>
                        bonjour
                    </body>
                </html>"#
            )
            .unwrap(),
            HashSet::from_iter(vec![
                "sha256-4+QNL+2odf47+35bV9by29lQ0daJMNTQRSLy7iRe3uI=".to_string()
            ])
        );
    }

    #[test]
    fn valid_html_with_style_and_script() {
        assert_eq!(
            csp_hashes_from_html_document(
                r#"<!doctype html>
                <html>
                    <head>
                        <title>woof</title>
                        <script>console.log("in head")</script>
                        <style> a { color: red } </style>
                        <style>
                            body {
                                font-family: cursive;
                            }
                        </style>
                    </head>
                    <body>
                        <script>console.log("in body")</script>
                    </body>
                </html>"#
            )
            .unwrap(),
            HashSet::from_iter(vec![
                "sha256-4+QNL+2odf47+35bV9by29lQ0daJMNTQRSLy7iRe3uI=".to_string(),
                "sha256-3oUpClVK/cNQB5x9TStM+xLiHETuIGGp2vGZRQdvHX0=".to_string(),
                "sha256-vjwjwnBndhWG+ZN6vpRKSmbicObZIQarx7RgSb3DmA8=".to_string(),
                "sha256-n1Yam9K1WJihP5yKcNNfCE/P1LaxJQmuUucwWsXrHWg=".to_string()
            ])
        );
    }
}
