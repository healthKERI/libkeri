use super::route::{compile_uri_template, Route, RouteResource};
use crate::cesr::indexing::siger::Siger;
use crate::cesr::prefixer::Prefixer;
use crate::cesr::saider::Saider;
use crate::cesr::seqner::Seqner;
use crate::cesr::Matter;
use crate::keri::core::serdering::Serder;
use crate::keri::core::serdering::SerderKERI;
use crate::keri::KERIError;
use std::collections::HashMap;
use tracing::debug;

/// Reply message router
///
/// Reply message router that accepts registration of route handlers and dispatches
/// reply messages to the appropriate handler.
pub struct Router {
    /// List of registered routes
    routes: Vec<Route>,
}

impl Router {
    /// Default resource function name
    pub const DEFAULT_RESOURCE_FUNC: &'static str = "processReply";

    /// Initialize Router instance with optional list of existing routes
    pub fn new(routes: Option<Vec<Route>>) -> Self {
        Self {
            routes: routes.unwrap_or_default(),
        }
    }

    /// Add a route between a route template and a resource
    ///
    /// # Parameters
    /// * `route_template` - A route template to use for the resource
    /// * `resource` - The resource instance to associate with the route template
    /// * `suffix` - Optional responder name suffix for this route. If a suffix is provided,
    ///             Router will map reply routes to processReply{suffix}(). In this way,
    ///             multiple closely-related routes can be mapped to the same resource.
    pub fn add_route(
        &mut self,
        route_template: &str,
        resource: Box<dyn RouteResource>,
        suffix: Option<String>,
    ) -> Result<(), KERIError> {
        let (fields, regex) = compile_uri_template(route_template)?;
        self.routes
            .push(Route::new(regex, fields, resource, suffix));
        Ok(())
    }

    /// Dispatch a reply message to the appropriate route handler
    ///
    /// # Parameters
    /// * `serder` - The reply message serder
    /// * `saider` - The SAID of the reply message
    /// * `cigars` - Optional non-transferable signature instances
    /// * `tsgs` - Optional transferable signature groups
    pub fn dispatch(
        &self,
        serder: &SerderKERI,
        saider: &Saider,
        cigars: Option<&[Siger]>,
        tsgs: Option<&[(Prefixer, Seqner, Saider, Vec<Siger>)]>,
    ) -> Result<(), KERIError> {
        let ked = serder.ked();

        // Get route from the message
        let route = ked
            .get("r")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KERIError::ValueError("Missing route 'r' in message".to_string()))?;

        // Find matching route
        let (matched_route, captured_params) = self.find_route(route)?;

        // Use the already extracted parameters
        let params = captured_params.unwrap_or_default();

        // Call the appropriate handler method
        matched_route
            .resource
            .process_reply(serder, saider, route, cigars, tsgs, params)
    }

    /// Linear search through added routes, returning the first one that matches
    ///
    /// Searches through the registered routes until a regex in one of the routes matches
    /// the provided route and returns the Route object along with the regex Match object.
    ///
    /// # Parameters
    /// * `route` - The route from the 'r' field of the reply message
    ///
    /// # Returns
    /// * The Route object with the resource that is registered to process this reply message
    /// * The regular expression match that contains the grouping of matched parameters
    fn find_route(
        &self,
        route: &str,
    ) -> Result<(&Route, Option<HashMap<String, String>>), KERIError> {
        for registered_route in &self.routes {
            if let Some(captures) = registered_route.regex.captures(route) {
                let mut captured_params = HashMap::new();
                for field_name in &registered_route.fields {
                    if let Some(matched_value) = captures.name(field_name) {
                        captured_params
                            .insert(field_name.clone(), matched_value.as_str().to_string());
                    }
                }
                return Ok((registered_route, Some(captured_params)));
            }
        }

        Err(KERIError::ValidationError(format!(
            "No resource is registered to handle route {}",
            route
        )))
    }

    /// Get the number of registered routes
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Check if a route is registered
    pub fn has_route(&self, route: &str) -> bool {
        self.find_route(route).is_ok()
    }
}

/// Default route resource implementation for testing and fallback
pub struct DefaultRouteResource;

impl RouteResource for DefaultRouteResource {
    fn process_reply(
        &self,
        serder: &SerderKERI,
        saider: &Saider,
        route: &str,
        _cigars: Option<&[Siger]>,
        _tsgs: Option<&[(Prefixer, Seqner, Saider, Vec<Siger>)]>,
        params: HashMap<String, String>,
    ) -> Result<(), KERIError> {
        debug!(
            "DefaultRouteResource processing reply: route={}, said={}, params={:?}",
            route,
            saider.qb64(),
            params
        );

        // Default implementation just logs the message
        debug!("Reply message: {}", serder.pretty(None));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cesr::saider::Saider;
    use crate::keri::core::serdering::SerderKERI;
    use std::collections::HashMap;

    struct TestResource {
        pub called: std::sync::Arc<std::sync::Mutex<bool>>,
    }

    impl RouteResource for TestResource {
        fn process_reply(
            &self,
            _serder: &SerderKERI,
            _saider: &Saider,
            _route: &str,
            _cigars: Option<&[Siger]>,
            _tsgs: Option<&[(Prefixer, Seqner, Saider, Vec<Siger>)]>,
            _params: HashMap<String, String>,
        ) -> Result<(), KERIError> {
            let mut called = self.called.lock().unwrap();
            *called = true;
            Ok(())
        }
    }

    #[test]
    fn test_router_new() {
        let router = Router::new(None);
        assert_eq!(router.route_count(), 0);
    }

    #[test]
    fn test_router_add_route() {
        let mut router = Router::new(None);
        let resource = Box::new(DefaultRouteResource);

        router.add_route("/test", resource, None).unwrap();
        assert_eq!(router.route_count(), 1);
        assert!(router.has_route("/test"));
    }

    #[test]
    fn test_router_add_route_with_params() {
        let mut router = Router::new(None);
        let resource = Box::new(DefaultRouteResource);

        router.add_route("/books/{isbn}", resource, None).unwrap();
        assert_eq!(router.route_count(), 1);
        assert!(router.has_route("/books/123"));
        assert!(!router.has_route("/books"));
    }
}
