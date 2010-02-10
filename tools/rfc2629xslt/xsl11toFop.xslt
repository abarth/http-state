<!-- 
    Transform XSL 1.1 extensions to FOP extensions

    Copyright (c) 2006-2007, Julian Reschke (julian.reschke@greenbytes.de)
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of Julian Reschke nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
-->

<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
               xmlns:fo="http://www.w3.org/1999/XSL/Format"
               xmlns:fox="http://xml.apache.org/fop/extensions"
               version="1.0"
>

<!-- transform bookmark elements -->

<xsl:template match="fo:bookmark-tree" >
  <xsl:apply-templates/>
</xsl:template>

<xsl:template match="fo:bookmark" >
  <fox:outline internal-destination="{@internal-destination}">
    <xsl:apply-templates/>
  </fox:outline>
</xsl:template>

<xsl:template match="fo:bookmark-title" >
  <fox:label>
    <xsl:apply-templates/>
  </fox:label>
</xsl:template>


<!-- work around for missing page break stuff -->

<xsl:template match="fo:block[@page-break-before='always']">
  <xsl:copy>
    <xsl:attribute name="break-before">page</xsl:attribute>
    <xsl:attribute name="keep-with-previous">auto</xsl:attribute>
    <xsl:apply-templates select="@*[not(name()='page-break-before') and not(name()='id')]" />
    <xsl:apply-templates select="@id" />
    <xsl:apply-templates select="node()" />
  </xsl:copy>
</xsl:template>

<!-- work around weird list item behaviour -->

<xsl:template match="fo:list-item-body/fo:block[not(node())]">
  <xsl:copy>
    <xsl:apply-templates select="@*"/>
    <!-- add NBSP so the block is not empty -->
    <xsl:text>&#160;</xsl:text>
  </xsl:copy>
</xsl:template>

<!-- add destination elements where IDs are defined -->
<xsl:template match="@id">
  <xsl:copy-of select="."/>
  <fox:destination internal-destination="{.}"/>
</xsl:template>

<xsl:template match="fo:list-item/@id">
  <!-- dunno how to in list items, so move into list-item-body -->
</xsl:template>

<xsl:template match="fo:list-item[@id]/fo:list-item-body">
  <xsl:copy>
    <xsl:attribute name="id"><xsl:value-of select="../@id"/></xsl:attribute>
    <xsl:apply-templates select="@*|node()"/>
  </xsl:copy>
</xsl:template>

<!-- index-page-citation-list -->

<xsl:attribute-set name="internal-link">
  <xsl:attribute name="color">#000080</xsl:attribute>
</xsl:attribute-set>

<xsl:template match="fo:index-page-citation-list">
  <xsl:variable name="items" select="fo:index-key-reference"/>
  <xsl:variable name="entries" select="//*[@index-key=$items/@ref-index-key]"/>
  <xsl:for-each select="$entries">
    <fo:basic-link internal-destination="{ancestor-or-self::*/@id}" xsl:use-attribute-sets="internal-link">
      <xsl:if test="contains(@index-key,',primary') and substring-after(@index-key,',primary')=''">
        <xsl:attribute name="font-weight">bold</xsl:attribute>
      </xsl:if>
      <fo:page-number-citation ref-id="{ancestor-or-self::*/@id}"/>
      <xsl:if test="not(ancestor-or-self::*/@id)">
        <xsl:message>WARNING: No ID found for <xsl:value-of select="@index-key"/>.</xsl:message>
      </xsl:if>
    </fo:basic-link>
    <xsl:if test="position()!=last()"><xsl:text>, </xsl:text></xsl:if>
  </xsl:for-each>
</xsl:template>

<!-- suppress and map-->
<xsl:template match="@index-key" />
<xsl:template match="fo:index-range-end" />
<xsl:template match="fo:index-range-begin">
  <fo:wrapper id="{@id}"/>
</xsl:template>

<!-- remove stuff not understood -->
<xsl:template match="@page-break-inside"/>

<!-- remove third-party extensions -->

<xsl:template match="*[namespace-uri()!='http://www.w3.org/1999/XSL/Format' and namespace-uri()!='http://xml.apache.org/fop/extensions']" />
<xsl:template match="@*[namespace-uri()!='' and namespace-uri()!='http://www.w3.org/1999/XSL/Format' and namespace-uri()!='http://xml.apache.org/fop/extensions']" />



<xsl:template match="node()|@*">
  <xsl:copy>
    <xsl:apply-templates select="@*[not(name()='id')]" />
    <xsl:apply-templates select="@id" />
    <xsl:apply-templates select="node()" />
  </xsl:copy>
</xsl:template>

<xsl:template match="/">
	<xsl:copy><xsl:apply-templates select="node()" /></xsl:copy>
</xsl:template>

</xsl:transform>