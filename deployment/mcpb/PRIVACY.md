# Data handling for the AI Native System MCP Bundle

The bundle runs as a local stdio process. Configure the API origin operated by your organization or service provider and a bearer token issued for that deployment. The MCP client supplies the token as a sensitive environment setting.

The adapter sends the token and requested task identifiers to that origin over HTTPS, or over HTTP to a local loopback origin. It calls the applications and task read endpoints. The deployment applies its own access controls and returns authorized results to your MCP client. The adapter has no telemetry endpoint.

The deployment operator determines how requests, credentials, and results are processed and retained. Consult the operator's privacy notice and the MCP client's settings before connecting a deployment.
