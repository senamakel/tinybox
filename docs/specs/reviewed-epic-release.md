# Reviewed-epic module releases

TinyBox supports two release entry points. A pushed `v*` tag and the default
manual `main` route use the existing canonical module-release workflow and its
fixed `tinybox-module` profile. Their inputs, reusable-workflow revision,
package name, and asset profile remain unchanged.

An operator may choose the `reviewed-epic` route in the manual Release
workflow. That route requires a positive integer canonical pull request number
whose merge commit the existing tag identifies. The workflow passes that
number to the shared reviewed-module-release workflow, which checks the
canonical repository profile and approved epic base before checking out the
admitted source, then verifies reviewed history and CI evidence before
packaging. The shared workflow is called at the fixed reviewed-release commit
`837d0424c7f38e4293f41c795f12ed5eb5dd7280`.

The reviewed PR number is invalid on the ordinary route. Missing, zero,
negative, fractional, or nonnumeric PR values fail before either release job
runs. Push-triggered tags always select the ordinary route. The release
workflow accepts no caller-selected repository, package, or reusable-workflow
revision. Top-level permissions remain empty; each reusable job receives only
the permissions required by its route.

The focused workflow test executes the actual inline resolve script from an
empty working directory with representative manual and tag-triggered
environments and checks route exclusivity, exact reusable-workflow pins, fixed
package profile, and permissions. The ordinary route always forwards a
numeric zero sentinel; the reviewed route requires a positive integer. CI runs
this Python test without adding another Rust build or test job.
