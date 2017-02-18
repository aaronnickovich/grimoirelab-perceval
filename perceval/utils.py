# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017 Bitergia
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA.
#
# Authors:
#     Santiago Dueñas <sduenas@bitergia.com>
#     Germán Poo-Caamaño <gpoo@gnome.org>
#

import datetime
import email
import inspect
import logging
import mailbox
import re
import sys

import xml.etree.ElementTree

import dateutil.parser
import dateutil.rrule
import dateutil.tz

import requests

from .errors import InvalidDateError, ParseError


logger = logging.getLogger(__name__)


DEFAULT_DATETIME = datetime.datetime(1970, 1, 1, 0, 0, 0,
                                     tzinfo=dateutil.tz.tzutc())


def check_compressed_file_type(filepath):
    """Check if filename is a compressed file supported by the tool.

    This function uses magic numbers (first four bytes) to determine
    the type of the file. Supported types are 'gz' and 'bz2'. When
    the filetype is not supported, the function returns `None`.

    :param filepath: path to the file

    :returns: 'gz' or 'bz2'; `None` if the type is not supported
    """
    def compressed_file_type(content):
        magic_dict = {
            b'\x1f\x8b\x08': 'gz',
            b'\x42\x5a\x68': 'bz2'
        }

        for magic, filetype in magic_dict.items():
            if content.startswith(magic):
                return filetype

        return None

    with open(filepath, mode='rb') as f:
        magic_number = f.read(4)
    return compressed_file_type(magic_number)


def months_range(from_date, to_date):
    """Generate a months range.

    Generator of months starting on `from_date` util `to_date`. Each
    returned item is a tuple of two datatime objects like in (month, month+1).
    Thus, the result will follow the sequence:
        ((fd, fd+1), (fd+1, fd+2), ..., (td-2, td-1), (td-1, td))

    :param from_date: generate dates starting on this month
    :param to_date: generate dates until this month

    :result: a generator of months range
    """
    start = datetime.datetime(from_date.year, from_date.month, 1)
    end = datetime.datetime(to_date.year, to_date.month, 1)

    month_gen = dateutil.rrule.rrule(freq=dateutil.rrule.MONTHLY,
                                     dtstart=start, until=end)
    months = [d for d in month_gen]

    pos = 0
    for x in range(1, len(months)):
        yield months[pos], months[x]
        pos = x


def datetime_utcnow():
    """Handy function which returns the current date and time in UTC."""

    return datetime.datetime.utcnow()


def datetime_to_utc(ts):
    """Convert a timestamp to UTC+0 timezone.

    Returns the given datetime object converted to a date with
    UTC+0 timezone. For naive datetimes, it will be assumed that
    they are in UTC+0.

    :param dt: timestamp to convert

    :returns: a datetime object

    :raises InvalidDateError: when the given parameter is not an
        instance of datetime
    """
    if not isinstance(ts, datetime.datetime):
        msg = '<%s> object' % type(ts)
        raise InvalidDateError(date=msg)

    if not ts.tzinfo:
        ts = ts.replace(tzinfo=dateutil.tz.tzutc())

    return ts.astimezone(dateutil.tz.tzutc())


def str_to_datetime(ts):
    """Format a string to a datetime object.

    This functions supports several date formats like YYYY-MM-DD,
    MM-DD-YYYY, YY-MM-DD, YYYY-MM-DD HH:mm:SS +HH:MM, among others.
    When the timezone is not provided, UTC+0 will be set as default
    (using `dateutil.tz.tzutc` object).

    :param ts: string to convert

    :returns: a datetime object

    :raises IvalidDateError: when the given string cannot be converted into
        a valid date
    """
    def parse_datetime(ts):
        dt = dateutil.parser.parse(ts)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=dateutil.tz.tzutc())
        return dt

    if not ts:
        raise InvalidDateError(date=str(ts))

    try:
        # Try to remove additional information after
        # timezone section because it cannot be parsed,
        # like in 'Wed, 26 Oct 2005 15:20:32 -0100 (GMT+1)'
        # or in 'Thu, 14 Aug 2008 02:07:59 +0200 CEST'.
        m = re.search(r"^.+?\s+[\+\-]\d{4}(\s+.+)$", ts)
        if m:
            ts = ts[:m.start(1)]

        try:
            dt = parse_datetime(ts)
        except ValueError as e:
            # Try to remove the timezone, usually it causes
            # problems. If it doesn't work, raise an exception
            m = re.search(r"^(.+?)\s+[\+\-]\d+$", ts)

            if not m:
                raise e

            dt = parse_datetime(m.group(1))

            logger.warning("Date %s str does not have a valid timezone", ts)
            logger.warning("Date converted removing timezone info")

        return dt
    except ValueError as e:
        raise InvalidDateError(date=str(ts))


def unixtime_to_datetime(ut):
    """Convert a unixtime timestamp to a datetime object.

    The function converts a timestamp in Unix format to a
    datetime object. UTC timezone will also be set.

    :param ut: Unix timestamp to convert

    :returns: a datetime object

    :raises InvalidDateError: when the given timestamp cannot be
        converted into a valid date
    """
    try:
        dt = datetime.datetime.utcfromtimestamp(ut)
        dt = dt.replace(tzinfo=dateutil.tz.tzutc())
        return dt
    except Exception:
        raise InvalidDateError(date=str(ut))


def urljoin(*args):
    """Joins given arguments into a URL.

    Trailing and leading slashes are stripped for each argument.

    This code is based on a Rune Kaagaard's answer on StackOverflow.
    See http://stackoverflow.com/questions/1793261 for more into. The
    code was licensed as cc by-sa 3.0.

    :params *args: list of arguments to join

    :returns: a URL string
    """
    return '/'.join(map(lambda x: str(x).strip('/'), args))


def message_to_dict(msg):
    """Convert an email message into a dictionary.

    This function transforms an `email.message.Message` object
    into a dictionary. Headers are stored as key:value pairs
    while the body of the message is stored inside `body` key.
    Body may have two other keys inside, 'plain', for plain body
    messages and 'html', for HTML encoded messages.

    The returned dictionary has the type `requests.structures.CaseInsensitiveDict`
    due to same headers with different case formats can appear in
    the same message.

    :param msg: email message of type `email.message.Message`

    :returns : dictionary of type `requests.structures.CaseInsensitiveDict`

    :raises ParseError: when an error occurs transforming the message
        to a dictionary
    """
    def parse_headers(msg):
        headers = {}

        for header, value in msg.items():
            hv = []

            for text, charset in email.header.decode_header(value):
                if type(text) == bytes:
                    charset = charset if charset else 'utf-8'
                    try:
                        text = text.decode(charset, errors='surrogateescape')
                    except (UnicodeError, LookupError):
                        # Try again with a 7bit encoding
                        text = text.decode('ascii', errors='surrogateescape')
                hv.append(text)

            v = ' '.join(hv)
            headers[header] = v if v else None

        return headers

    def parse_payload(msg):
        body = {}

        if not msg.is_multipart():
            payload = decode_payload(msg)
            subtype = msg.get_content_subtype()
            body[subtype] = [payload]
        else:
            # Include all the attached texts if it is multipart
            # Ignores binary parts by default
            for part in email.iterators.typed_subpart_iterator(msg):
                payload = decode_payload(part)
                subtype = part.get_content_subtype()
                body.setdefault(subtype, []).append(payload)

        return {k : '\n'.join(v) for k, v in body.items()}

    def decode_payload(msg_or_part):
        charset = msg_or_part.get_content_charset('utf-8')
        payload = msg_or_part.get_payload(decode=True)

        try:
            payload = payload.decode(charset, errors='surrogateescape')
        except (UnicodeError, LookupError):
            # Try again with a 7bit encoding
            payload = payload.decode('ascii', errors='surrogateescape')
        return payload

    # The function starts here
    message = requests.structures.CaseInsensitiveDict()

    if isinstance(msg, mailbox.mboxMessage):
        message['unixfrom'] = msg.get_from()
    else:
        message['unixfrom'] = None

    try:
        for k, v in parse_headers(msg).items():
            message[k] = v
        message['body'] = parse_payload(msg)
    except UnicodeError as e:
        raise ParseError(cause=str(e))

    return message


def remove_invalid_xml_chars(raw_xml):
    """Remove control and invalid characters from an xml stream.

    Looks for invalid characters and subtitutes them with whitespaces.
    This solution is based on these two posts: Olemis Lang's reponse
    on StackOverflow (http://stackoverflow.com/questions/1707890) and
    lawlesst's on GitHub Gist (https://gist.github.com/lawlesst/4110923),
    that is based on the previous answer.

    :param xml: XML stream

    :returns: a purged XML stream
    """
    illegal_unichrs = [(0x00, 0x08), (0x0B, 0x1F),
                       (0x7F, 0x84), (0x86, 0x9F)]

    illegal_ranges = ['%s-%s' % (chr(low), chr(high))
                      for (low, high) in illegal_unichrs
                      if low < sys.maxunicode]

    illegal_xml_re = re.compile('[%s]' % ''.join(illegal_ranges))

    purged_xml = ''

    for c in raw_xml:
        if illegal_xml_re.search(c) is not None:
            c = ' '
        purged_xml += c

    return purged_xml


def xml_to_dict(raw_xml):
    """Convert a XML stream into a dictionary.

    This function transforms a xml stream into a dictionary. The
    attributes are stored as single elements while child nodes are
    stored into lists. The text node is stored using the special
    key '__text__'.

    This code is based on Winston Ewert's solution to this problem.
    See http://codereview.stackexchange.com/questions/10400/convert-elementtree-to-dict
    for more info. The code was licensed as cc by-sa 3.0.

    :param raw_xml: XML stream

    :returns: a dict with the XML data

    :raises ParseError: raised when an error occurs parsing the given
        XML stream
    """
    def node_to_dict(node):
        d = {}
        d.update(node.items())

        text = getattr(node, 'text', None)

        if text is not None:
            d['__text__'] = text

        childs = {}
        for child in node:
            childs.setdefault(child.tag, []).append(node_to_dict(child))

        d.update(childs.items())

        return d

    purged_xml = remove_invalid_xml_chars(raw_xml)

    try:
        tree = xml.etree.ElementTree.fromstring(purged_xml)
    except xml.etree.ElementTree.ParseError as e:
        cause = "XML stream %s" % (str(e))
        raise ParseError(cause=cause)

    d = node_to_dict(tree)

    return d


def build_signature_parameters(candidates, callable_):
    """Build from a set of candidates the parameters needed to exec a callable.

    Returns a dict with the `candidates` found on `callable_`. When
    any of the required parameters of a callable is not found, it
    raises a `AttributeError` exception.

    :param candidates: dict with the names of the possible parameters
        and their values
    :param callable_: callable object

    :result: dict with the parameters needed to call `callable_`
    """
    to_match = inspect_signature_parameters(callable_)

    result = {}

    for p in to_match:
        name = p.name
        if name in candidates:
            result[name] =  candidates[name]
        elif p.default == inspect.Parameter.empty:
            # Parameters which its default value is empty are
            # considered as required
            raise AttributeError("required argument %s not found" % name,
                                 name)
    return result


def inspect_signature_parameters(callable_):
    """Get the parameters of a callable.

    Returns a list with the signature parameters of `callable_`.
    Parameters 'self' and 'cls' are filtered from the result.

    :param callable_: callable object

    :result: list of parameters
    """
    signature = inspect.signature(callable_)
    params = [v for p, v in signature.parameters.items() \
              if p not in ('self', 'cls')]
    return params
