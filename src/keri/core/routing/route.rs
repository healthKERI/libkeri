use regex::Regex;
use std::collections::HashSet;

/// Route class for registration of reply message handlers
///
/// This class represents a registered route internally to the Router.
/// The properties are created by using the compile route utility method
pub struct Route {
    /// Compiled URI template regex
    pub regex: Regex,

    /// Field names for matches in regex
    pub fields: HashSet<String>,

    /// The handler for this route (stored as type-erased trait object)
    pub resource: Box<dyn RouteResource>,

    /// A suffix to be applied to the handler method
    pub suffix: Option<String>,
}

impl Route {
    /// Initialize instance of route
    pub fn new(
        regex: Regex,
        fields: HashSet<String>,
        resource: Box<dyn RouteResource>,
        suffix: Option<String>,
    ) -> Self {
        Self {
            regex,
            fields,
            resource,
            suffix,
        }
    }
}

/// Trait that route resources must implement
pub trait RouteResource: Send + Sync {
    /// Default reply processing method
    fn process_reply(
        &self,
        serder: &crate::keri::core::serdering::SerderKERI,
        saider: &crate::cesr::saider::Saider,
        route: &str,
        cigars: Option<&[crate::cesr::indexing::siger::Siger]>,
        tsgs: Option<
            &[(
                crate::cesr::prefixer::Prefixer,
                crate::cesr::seqner::Seqner,
                crate::cesr::saider::Saider,
                Vec<crate::cesr::indexing::siger::Siger>,
            )],
        >,
        params: std::collections::HashMap<String, String>,
    ) -> Result<(), crate::keri::KERIError>;

    /// Method called when a route is not found - can be overridden
    fn process_route_not_found(
        &self,
        serder: &crate::keri::core::serdering::SerderKERI,
        saider: &crate::cesr::saider::Saider,
        route: &str,
        cigars: Option<&[crate::cesr::indexing::siger::Siger]>,
        tsgs: Option<
            &[(
                crate::cesr::prefixer::Prefixer,
                crate::cesr::seqner::Seqner,
                crate::cesr::saider::Saider,
                Vec<crate::cesr::indexing::siger::Siger>,
            )],
        >,
        params: std::collections::HashMap<String, String>,
    ) -> Result<(), crate::keri::KERIError> {
        Err(crate::keri::KERIError::ValueError(format!(
            "Resource registered for route {} does not contain the correct processReply method",
            route
        )))
    }
}

/// Compile the given URI template string into a pattern matcher
///
/// This function can be used to construct custom routing engines that
/// iterate through a list of possible routes, attempting to match
/// an incoming request against each route's compiled regular expression.
///
/// Each field is converted to a named group, so that when a match
/// is found, the fields can be easily extracted using the capture groups.
///
/// This function does not support the more flexible templating
/// syntax used in the default router. Only simple paths with bracketed
/// field expressions are recognized. For example:
///
///
/// /
/// /books
/// /books/{isbn}
/// /books/{isbn}/characters
/// /books/{isbn}/characters/{name}
///
///
/// Also, note that if the template contains a trailing slash character,
/// it will be stripped in order to normalize the routing logic.
///
/// # Arguments
/// * `template` - The template to compile. Note that field names are
///               restricted to ASCII a-z, A-Z, and the underscore character.
///
/// # Returns
/// * `(template_field_names, template_regex)`
pub fn compile_uri_template(
    template: &str,
) -> Result<(HashSet<String>, Regex), crate::keri::KERIError> {
    if !template.starts_with('/') {
        return Err(crate::keri::KERIError::ValueError(
            "uri_template must start with '/'".to_string(),
        ));
    }

    if template.contains("//") {
        return Err(crate::keri::KERIError::ValueError(
            "uri_template may not contain '//'".to_string(),
        ));
    }

    let mut normalized_template = template.to_string();
    if normalized_template != "/" && normalized_template.ends_with('/') {
        normalized_template.pop();
    }

    // Template names should be able to start with A-Za-z
    // but also contain 0-9_ in the remaining portion
    let expression_pattern = regex::Regex::new(r"\{([a-zA-Z]\w*)\}")
        .map_err(|e| crate::keri::KERIError::ValueError(format!("Invalid regex pattern: {}", e)))?;

    // Get a list of field names
    let mut fields = HashSet::new();
    for caps in expression_pattern.captures_iter(&normalized_template) {
        if let Some(field_name) = caps.get(1) {
            fields.insert(field_name.as_str().to_string());
        }
    }

    // Escape special regex characters except for our template patterns
    let mut escaped = String::new();
    for ch in normalized_template.chars() {
        match ch {
            '.' | '(' | ')' | '[' | ']' | '?' | '*' | '+' | '^' | '|' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }

    // Convert Level 1 var patterns to equivalent named regex groups
    let pattern = expression_pattern.replace_all(&escaped, r"(?P<$1>[^/]+)");
    let final_pattern = format!(r"^{}$", pattern);

    let regex = Regex::new(&final_pattern).map_err(|e| {
        crate::keri::KERIError::ValueError(format!("Invalid compiled regex: {}", e))
    })?;

    Ok((fields, regex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_uri_template_simple() {
        let (fields, regex) = compile_uri_template("/books").unwrap();
        assert!(fields.is_empty());
        assert!(regex.is_match("/books"));
        assert!(!regex.is_match("/books/123"));
    }

    #[test]
    fn test_compile_uri_template_with_param() {
        let (fields, regex) = compile_uri_template("/books/{isbn}").unwrap();
        assert_eq!(fields.len(), 1);
        assert!(fields.contains("isbn"));
        assert!(regex.is_match("/books/123"));
        assert!(!regex.is_match("/books/123/characters"));
    }

    #[test]
    fn test_compile_uri_template_multiple_params() {
        let (fields, regex) = compile_uri_template("/books/{isbn}/characters/{name}").unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields.contains("isbn"));
        assert!(fields.contains("name"));
        assert!(regex.is_match("/books/123/characters/alice"));
    }

    #[test]
    fn test_compile_uri_template_invalid() {
        assert!(compile_uri_template("books").is_err()); // doesn't start with /
        assert!(compile_uri_template("/books//test").is_err()); // contains //
    }

    #[test]
    fn test_compile_uri_template_trailing_slash() {
        let (fields, regex) = compile_uri_template("/books/").unwrap();
        assert!(fields.is_empty());
        assert!(regex.is_match("/books"));
        assert!(!regex.is_match("/books/"));
    }
}
