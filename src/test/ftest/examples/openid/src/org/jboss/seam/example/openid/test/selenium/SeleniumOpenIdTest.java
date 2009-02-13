package org.jboss.seam.example.openid.test.selenium;

import static org.testng.AssertJUnit.assertEquals;

import org.jboss.seam.example.common.test.selenium.SeamSeleniumTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class SeleniumOpenIdTest extends SeamSeleniumTest
{
   public static final String HOME_PAGE_TITLE = "OpenID Wall";

   @BeforeMethod
   @Override
   public void setUp()
   {
      super.setUp();
      browser.open(CONTEXT_PATH);
   }

   /**
    * Place holder - just verifies that example deploys
    */
   @Test
   public void homePageLoadTest()
   {
      assertEquals("Unexpected page title.", HOME_PAGE_TITLE, browser.getTitle());
   }
}
