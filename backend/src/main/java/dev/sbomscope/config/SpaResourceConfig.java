package dev.sbomscope.config;

import java.io.IOException;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;

/**
 * Serves the React build from the classpath and makes client-side routing survive a
 * browser refresh.
 *
 * <p>The frontend module packages its Vite output under {@code META-INF/resources}, so a
 * deep link such as {@code /settings} arrives here as a request for a static file that
 * does not exist. Anything that is not a real file and not an API call is answered with
 * {@code index.html}, letting the router take over on the client.
 */
@Configuration
class SpaResourceConfig implements WebMvcConfigurer {

    private static final String UI_LOCATION = "classpath:/META-INF/resources/";
    private static final String INDEX_HTML = "/META-INF/resources/index.html";

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**")
                .addResourceLocations(UI_LOCATION)
                .resourceChain(true)
                .addResolver(new SpaFallbackResolver());
    }

    private static final class SpaFallbackResolver extends PathResourceResolver {

        @Override
        protected Resource getResource(String resourcePath, Resource location) throws IOException {
            Resource requested = location.createRelative(resourcePath);
            if (requested.exists() && requested.isReadable()) {
                return requested;
            }

            // API paths must keep returning 404 rather than the UI shell: a mistyped
            // fetch URL should fail as a missing endpoint, not as an HTML parse error.
            if (resourcePath.startsWith("api/")) {
                return null;
            }

            return new ClassPathResource(INDEX_HTML);
        }
    }
}
