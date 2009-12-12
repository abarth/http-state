# Copyright (c) 2009, Adam Barth. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the Adam Barth nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY ADAM BARTH ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

class CookieAttribute(object):
    """Represents an attribute of a cookie."""

    @staticmethod
    def parse_httponly(value):
        return None

    @staticmethod
    def parse_max_age(value):
        return None # FIXME 

    @staticmethod
    def parse_expires(value):
        return None # FIXME 

    def __init__(self, name, value):
        parse_value = {
            "max-age": self.parse_max_age,
            "expires": self.parse_expires,
            "httponly": self.parse_httponly,
        }

        self.name = name.lower()
        self.value = parse_value[name](value)


class SetCookieHeaderField(object):
    """Represents a Set-Cookie header field."""

    @staticmethod
    def split_on_semicolon(string):
        semicolon_index = string.find(';')
        if semicolon_index < 0:
            return string, ''
        return string[:semicolon_index], string[semicolon_index:]

    @staticmethod
    def split_on_and_consume_equal_sign(string):
        equal_sign_index = string.find('=')
        if equal_sign_index < 0:
            return string, ''
        return string[:equal_sign_index], string[equal_sign_index+1:]

    @staticmethod
    def trim_space(string):
        return string.lstrip('\x20').rstrip('\x20')

    @staticmethod
    def parse_attributes(unparsed_attributes):
        while len(unparsed_attributes):
            assert(unparsed_attributes[index] == ';')
            unparsed_attributes = unparsed_attributes[1:]
            attribute_value_pair, unparsed_attributes = self.split_on_semicolon(unparsed_attributes)
            self.parse_attribute_value_pair(attribute_value_pair)

    @staticmethod
    def parse_attribute_value_pair(attribute_value_pair):
        name, value = self.split_on_and_consume_equal_sign(attribute_value_pair)
        name = self.trim_space(name).lower()
        value = self.trim_space(value)
        self.cookie_attribute_list.append(CookieAttribute(name, value))

    def __init__(self, header_field):
        name_value_pair, unparsed_attributes = self.split_on_semicolon(header_field)
        # Notice that a name_value_pair without an '=' is consided a value.
        value, name = self.split_on_and_consume_equal_sign(name_value_pair)
        self.cookie_name = self.trim_space(name)
        self.cookie_value = self.trim_space(value)
        self.cookie_attribute_list = []
        self.parse_attributes(unparsed_attributes)

