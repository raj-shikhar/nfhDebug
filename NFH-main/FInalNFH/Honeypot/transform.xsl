<!-- transform.xsl -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" indent="yes"/>
  
  <!-- Template to match any element -->
  <xsl:template match="*">
    <xsl:element name="{name()}">
      <!-- Apply templates to child nodes -->
      <xsl:apply-templates/>
    </xsl:element>
  </xsl:template>
  
  <!-- Template to match text nodes -->
  <xsl:template match="text()">
    <xsl:value-of select="."/>
  </xsl:template>
</xsl:stylesheet>
