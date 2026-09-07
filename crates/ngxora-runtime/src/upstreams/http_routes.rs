use ngxora_compile::ir::{HttpMatch, HttpPathMatch, HttpRedirect, PathModifier};
use std::collections::HashSet;

pub(crate) fn normalize_hostname(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

// The suffix length also gives the wildcard's precedence.
pub(crate) fn hostname_score(pattern: &str, host: &str) -> Option<(bool, usize)> {
    if pattern == host {
        return Some((true, pattern.len()));
    }
    let suffix = pattern.strip_prefix('*')?;
    (suffix.starts_with('.') && host.len() > suffix.len() && host.ends_with(suffix))
        .then_some((false, suffix.len()))
}

pub(crate) fn validate_hostname(host: &str) -> Result<(), String> {
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(format!("invalid hostname `{host}`"));
    }
    Ok(())
}

pub(crate) fn prefix_matches(prefix: &str, path: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|tail| tail.starts_with('/'))
}

pub(crate) fn compile_match(input: &HttpMatch) -> Result<HttpMatch, String> {
    let mut result = input.clone();
    match &input.path {
        HttpPathMatch::Exact(path) | HttpPathMatch::PathPrefix(path) => validate_path(path)?,
    }
    if let HttpPathMatch::PathPrefix(path) = &mut result.path {
        *path = path.trim_end_matches('/').to_string();
        if path.is_empty() {
            *path = "/".into();
        }
    }
    if let Some(method) = &result.method {
        http::Method::from_bytes(method.as_bytes()).map_err(|_| "invalid HTTP match method")?;
    }
    let mut seen = HashSet::new();
    for (name, value) in &mut result.headers {
        *name = http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "invalid HTTP match header name")?
            .as_str()
            .to_string();
        http::HeaderValue::from_str(value).map_err(|_| "invalid HTTP match header value")?;
    }
    result.headers.retain(|(name, _)| seen.insert(name.clone()));
    seen.clear();
    result
        .query_params
        .retain(|(name, _)| seen.insert(name.clone()));
    Ok(result)
}

pub(crate) fn match_score(m: &HttpMatch) -> (bool, usize, bool, usize, usize) {
    let (exact, len) = match &m.path {
        HttpPathMatch::Exact(path) => (true, path.len()),
        HttpPathMatch::PathPrefix(path) => (false, path.len()),
    };
    (
        exact,
        len,
        m.method.is_some(),
        m.headers.len(),
        m.query_params.len(),
    )
}

pub(crate) fn matches(m: &HttpMatch, request: &pingora::http::RequestHeader) -> bool {
    let path_matches = match &m.path {
        HttpPathMatch::Exact(path) => path == request.uri.path(),
        HttpPathMatch::PathPrefix(path) => prefix_matches(path, request.uri.path()),
    };
    path_matches
        && m.method
            .as_ref()
            .is_none_or(|method| method == request.method.as_str())
        && m.headers.iter().all(|(name, value)| {
            request
                .headers
                .get(name)
                .is_some_and(|header| header.as_bytes() == value.as_bytes())
        })
        && m.query_params.iter().all(|(name, value)| {
            url::form_urlencoded::parse(request.uri.query().unwrap_or("").as_bytes())
                .find(|(key, _)| key == name)
                .is_some_and(|(_, actual)| actual == value.as_str())
        })
}

fn validate_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/')
        || path.contains(['?', '#'])
        || path.contains("//")
        || path.parse::<http::uri::PathAndQuery>().is_err()
    {
        return Err(format!("invalid HTTP path `{path}`"));
    }
    Ok(())
}

pub(crate) fn validate_modifier(
    modifier: Option<&PathModifier>,
    matcher: &super::types::CompiledMatcher,
) -> Result<(), String> {
    if let Some(modifier) = modifier {
        let path = match modifier {
            PathModifier::ReplaceFullPath(path) => path,
            PathModifier::ReplacePrefixMatch(path) => {
                if !matches!(
                    matcher,
                    super::types::CompiledMatcher::Http(HttpMatch {
                        path: HttpPathMatch::PathPrefix(_),
                        ..
                    })
                ) {
                    return Err("ReplacePrefixMatch requires an HTTP PathPrefix match".into());
                }
                path
            }
        };
        // Empty replacement removes the matched prefix.
        if !path.is_empty() || matches!(modifier, PathModifier::ReplaceFullPath(_)) {
            validate_path(path)?;
        }
    }
    Ok(())
}

pub(crate) fn rewrite_uri(
    uri: &http::Uri,
    modifier: Option<&PathModifier>,
    prefix: Option<&str>,
) -> Result<http::Uri, String> {
    let path = match modifier {
        None => uri.path().to_string(),
        Some(PathModifier::ReplaceFullPath(path)) => path.clone(),
        Some(PathModifier::ReplacePrefixMatch(replacement)) => {
            let prefix = prefix
                .ok_or("missing matched path prefix")?
                .trim_end_matches('/');
            let suffix = uri
                .path()
                .strip_prefix(prefix)
                .ok_or("path does not match rewrite prefix")?;
            let mut path = if suffix.is_empty() {
                replacement.clone()
            } else {
                format!("{}{}", replacement.trim_end_matches('/'), suffix)
            };
            if path.is_empty() {
                path.push('/');
            }
            path
        }
    };
    let full = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    full.parse()
        .map_err(|e| format!("invalid rewritten URI: {e}"))
}

pub(crate) fn redirect_location(
    config: &HttpRedirect,
    uri: &http::Uri,
    host: &str,
    scheme: &str,
    listener_port: u16,
    prefix: Option<&str>,
) -> Result<String, String> {
    let scheme = config.scheme.as_deref().unwrap_or(scheme);
    let port = config
        .port
        .unwrap_or_else(|| match config.scheme.as_deref() {
            Some("https") => 443,
            Some("http") => 80,
            _ => listener_port,
        });
    let host = config.hostname.as_deref().unwrap_or(host);
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let authority = if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        host
    } else {
        format!("{host}:{port}")
    };
    let uri = rewrite_uri(uri, config.path.as_ref(), prefix)?;
    Ok(format!("{scheme}://{authority}{uri}"))
}

pub(crate) fn expand_return(
    template: &str,
    host: &str,
    uri: &str,
    scheme: &str,
) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(index) = rest.find('$') {
        out.push_str(&rest[..index]);
        rest = &rest[index + 1..];
        if let Some(tail) = rest.strip_prefix('$') {
            out.push('$');
            rest = tail;
            continue;
        }
        let len = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        let value = match &rest[..len] {
            "host" => host,
            "request_uri" => uri,
            "scheme" => scheme,
            name => return Err(format!("unsupported return variable `${name}`")),
        };
        out.push_str(value);
        rest = &rest[len..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(path: &str) -> HttpMatch {
        HttpMatch {
            path: HttpPathMatch::PathPrefix(path.into()),
            method: None,
            headers: vec![],
            query_params: vec![],
        }
    }

    #[test]
    fn http_prefix_validation_and_boundaries() {
        for path in ["", "//", "/foo//", "foo", "/foo?q=1", "/foo#bar"] {
            assert!(compile_match(&matcher(path)).is_err(), "{path}");
        }
        for path in ["/foo", "/foo/", "/foo/bar"] {
            assert!(prefix_matches("/foo/", path));
        }
        for path in ["/foobar", "/Foo", "/foo%2Fbar"] {
            assert!(!prefix_matches("/foo", path));
        }
        assert!(prefix_matches("/", "/anything"));
        assert_eq!(
            compile_match(&matcher("/foo/")).unwrap().path,
            HttpPathMatch::PathPrefix("/foo".into())
        );
    }

    #[test]
    fn hostname_precedence_and_label_boundaries() {
        let exact = hostname_score("a.b.example.com", "a.b.example.com").unwrap();
        let specific = hostname_score("*.b.example.com", "a.b.example.com").unwrap();
        let broad = hostname_score("*.example.com", "a.b.example.com").unwrap();
        assert!(exact > specific && specific > broad);
        assert!(hostname_score("*.example.com", "example.com").is_none());
        assert!(hostname_score("*.example.com", "badexample.com").is_none());
    }

    #[test]
    fn prefix_rewrites_preserve_suffix_and_query() {
        for (input, replacement, expected) in [
            ("/foo", "/bar", "/bar"),
            ("/foo/", "/bar", "/bar/"),
            ("/foo/a%2Fb?q=%2F", "/bar/", "/bar/a%2Fb?q=%2F"),
            ("/foo", "", "/"),
            ("/foo/a", "/", "/a"),
        ] {
            let uri = rewrite_uri(
                &input.parse().unwrap(),
                Some(&PathModifier::ReplacePrefixMatch(replacement.into())),
                Some("/foo"),
            )
            .unwrap();
            assert_eq!(uri.to_string(), expected);
        }
        assert_eq!(
            rewrite_uri(
                &"/old?q=1".parse().unwrap(),
                Some(&PathModifier::ReplaceFullPath("/new/".into())),
                None
            )
            .unwrap()
            .to_string(),
            "/new/?q=1"
        );
    }

    #[test]
    fn redirect_defaults_ports_and_return_variables() {
        let mut config = HttpRedirect {
            status: 302,
            scheme: None,
            hostname: None,
            port: None,
            path: None,
        };
        let uri = "/foo?q=1".parse().unwrap();
        assert_eq!(
            redirect_location(&config, &uri, "example.com", "http", 8080, None).unwrap(),
            "http://example.com:8080/foo?q=1"
        );
        config.scheme = Some("https".into());
        assert_eq!(
            redirect_location(&config, &uri, "example.com", "http", 8080, None).unwrap(),
            "https://example.com/foo?q=1"
        );
        config.port = Some(8443);
        assert_eq!(
            redirect_location(&config, &uri, "::1", "http", 8080, None).unwrap(),
            "https://[::1]:8443/foo?q=1"
        );
        assert_eq!(
            expand_return(
                "$scheme://$host$request_uri?x=$$",
                "example.com",
                "/a",
                "https"
            )
            .unwrap(),
            "https://example.com/a?x=$"
        );
        assert!(expand_return("$unknown", "", "", "").is_err());
        assert!(expand_return("$hostname", "", "", "").is_err());
    }

    #[test]
    fn duplicate_conditions_use_first_value() {
        let mut input = matcher("/");
        input.headers = vec![
            ("X-Key".into(), "first".into()),
            ("x-key".into(), "second".into()),
        ];
        input.query_params = vec![("q".into(), "first".into()), ("q".into(), "second".into())];
        let compiled = compile_match(&input).unwrap();
        assert_eq!(compiled.headers, vec![("x-key".into(), "first".into())]);
        assert_eq!(compiled.query_params, vec![("q".into(), "first".into())]);
    }
}
