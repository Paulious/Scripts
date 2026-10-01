# Single front door: "/" goes to the web app, "/api/" goes to the analysis API.
# One address means one sign-in and no CORS. The nginx image fills in the
# ${...} placeholders from environment variables when the container starts.
FROM nginx:1.27-alpine
COPY default.conf.template /etc/nginx/templates/default.conf.template
ENV API_HOST=api WEB_HOST=web MAX_UPLOAD_MB=200
EXPOSE 8080
