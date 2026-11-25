package eu.wohlben.qits.certificates;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.junit.ArchTests;
import eu.wohlben.qits.archrules.HttpClientRules;

/**
 * The platform's shared ArchUnit rules over every class of this component — `domain` included,
 * which is why it lives in `service`, the one classpath that carries both modules: every HTTP
 * client is the platform's. There are no entities, so CausationRowRules and EntityExposureRules have
 * nothing to look at and are not listed.
 */
@AnalyzeClasses(
    packages = "eu.wohlben.qits.certificates",
    importOptions = ImportOption.DoNotIncludeTests.class)
class ArchRulesTest {

  @ArchTest static final ArchTests HTTP_CLIENTS = ArchTests.in(HttpClientRules.class);
}
