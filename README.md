# CSP-hashes

CSP-hashes is a utility for hashing scripts while creating a <a href="https://developer.mozilla.org/docs/Web/HTTP/CSP">Content Security Policy (CSP)</a>.

## Usage
```
let hashes = csp_hashes::csp_hashes_from_html_document(
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
); // {"sha384-8wiu0e3/t6a55K7REGqooaRsccJwaR4CH2UgjuPia5OjmnWavbRbuAk4NL+WJ07o", "sha384-DSCsjoY4lRFgW2ltWTCEhMG+WSglTblYcvUcCd/X4ua88hLymWLjdMdNAEXJF1R9"}
```