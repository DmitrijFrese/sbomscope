package dev.sbomscope.linkage;

/**
 * One member in JVM internal form.
 *
 * @param owner      internal class name, for example {@code com/example/Foo}
 * @param name       member name
 * @param descriptor JVM descriptor; a field's descriptor is its type
 */
public record MemberRef(String owner, String name, String descriptor) {}
