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
#

import json
import logging

import requests

from ...backend import Backend, metadata
from ...errors import BaseError
from ...utils import (DEFAULT_DATETIME,
                      datetime_to_utc,
                      datetime_utcnow,
                      urljoin)


logger = logging.getLogger(__name__)

SLACK_URL = 'https://slack.com/'
MAX_ITEMS = 1000


class Slack(Backend):
    """Slack backend.

    This class retrieves the messages sent to a Slack channel.
    To access the server an API token is required, which must
    have enough permissions to read from the given channel.

    The origin of the data will be set to the `SLACK_URL` plus the
    identifier of the channel; i.e 'https://slack.com/C01234ABC'.

    :param channel: identifier of the channel where data will be fetched
    :param api_token: token or key needed to use the API
    :param max_items: maximum number of message requested on the same query
    :param tag: label used to mark the data
    :param cache: cache object to store raw data
    """
    version = '0.1.0'

    def __init__(self, channel, api_token, max_items=MAX_ITEMS,
                 tag=None, cache=None):
        origin = urljoin(SLACK_URL, channel)

        super().__init__(origin, tag=tag, cache=cache)
        self.channel = channel
        self.max_items = max_items
        self.client = SlackClient(api_token, max_items=max_items)
        self._users = {}

    @metadata
    def fetch(self, from_date=DEFAULT_DATETIME):
        """Fetch the messages from the channel.

        This method fetches the messages stored on the channel that were
        sent since the given date.

        :param from_date: obtain messages sent since this date

        :returns: a generator of messages
        """
        logger.info("Fetching messages of '%s' channel from %s",
                    self.channel, str(from_date))

        oldest = datetime_to_utc(from_date).timestamp()
        latest = datetime_utcnow().timestamp()

        # Minimum value supported by Slack is 0 not 0.0
        if oldest == 0.0:
            oldest = 0

        # Slack does not include on its result the lower limit
        # of the search if it has the same date of 'oldest'. To get
        # this messages too, we substract a low value to be sure
        # the dates are not the same
        if oldest > 0.0:
            oldest -= .000001

        fetching = True
        nmsgs = 0

        while fetching:
            raw_history = self.client.history(self.channel,
                                              oldest=oldest, latest=latest)
            messages, fetching = self.parse_history(raw_history)

            for message in messages:
                message['user_data'] = self.__get_or_fetch_user(message['user'])
                yield message

                nmsgs += 1

                if fetching:
                    latest = float(message['ts'])

        logger.info("Fetch process completed: %s message fetched", nmsgs)

    def __get_or_fetch_user(self, user_id):
        if user_id in self._users:
            return self._users[user_id]

        logger.debug("User %s not found on client cache; fetching it", user_id)

        raw_user = self.client.user(user_id)
        user = self.parse_user(raw_user)

        self._users[user_id] = user
        return user

    @classmethod
    def has_caching(cls):
        """Returns whether it supports caching items on the fetch process.

        :returns: this backend does not support items cache
        """
        return False

    @classmethod
    def has_resuming(cls):
        """Returns whether it supports to resume the fetch process.

        :returns: this backend does not support items resuming
        """
        return False

    @staticmethod
    def metadata_id(item):
        """Extracts the identifier from a Slack item.

        This identifier will be the mix of two fields because Slack
        messages does not have any unique identifier. In this case,
        'ts' and 'nick' values are combined because there have been
        cases where two messages were sent by different users at
        the same time.
        """
        return item['ts'] + item['user']

    @staticmethod
    def metadata_updated_on(item):
        """Extracts and coverts the update time from a Slack item.

        The timestamp is extracted from 'ts' field and converted
        to a UNIX timestamp.

        :param item: item generated by the backend

        :returns: a UNIX timestamp
        """
        ts = float(item['ts'])

        return ts

    @staticmethod
    def metadata_category(item):
        """Extracts the category from a Slack item.

        This backend only generates one type of item which is
        'message'.
        """
        return 'message'

    @staticmethod
    def parse_history(raw_history):
        """Parse a channel history JSON stream.

        This method parses a JSON stream, containing the history of
        a channel, and returns a list with the parsed data. It also
        returns if there are more messages that are not included on
        this stream.

        :param raw_history: JSON string to parse

        :returns: a tuple with a list of dicts with the parsed messages
            and 'has_more' value
        """
        result = json.loads(raw_history)
        return result['messages'], result['has_more']

    @staticmethod
    def parse_user(raw_user):
        """Parse a user's info JSON stream.

        This method parses a JSON stream, containing the information
        from a user, and returns a dict with the parsed data.

        :param raw_user: JSON string to parse

        :returns: a dict with the parsed user's information
        """
        result = json.loads(raw_user)
        return result['user']


class SlackClientError(BaseError):
    """Raised when an error occurs using the Slack client"""

    message = "%(error)s"


class SlackClient:
    """Slack API client.

    Client for fetching information from the Slack server
    using its REST API.

    :param api_key: key needed to use the API
    :param max_items: maximum number of items per request
    """
    URL = urljoin(SLACK_URL, 'api', '%(resource)s')

    RCHANNEL_HISTORY = 'channels.history'
    RUSER_INFO = 'users.info'

    PCHANNEL = 'channel'
    PCOUNT = 'count'
    POLDEST = 'oldest'
    PLATEST = 'latest'
    PTOKEN = 'token'
    PUSER = 'user'

    def __init__(self, api_token, max_items=MAX_ITEMS):
        self.api_token = api_token
        self.max_items = max_items

    def history(self, channel, oldest=None, latest=None):
        """Fetch the history of a channel."""

        resource = self.RCHANNEL_HISTORY

        params = {
            self.PCHANNEL : channel,
            self.PCOUNT : self.max_items
        }

        if oldest is not None:
            params[self.POLDEST] = oldest
        if latest is not None:
            params[self.PLATEST] = latest

        response = self._fetch(resource, params)

        return response

    def user(self, user_id):
        """Fetch user info."""

        resource = self.RUSER_INFO

        params = {
            self.PUSER : user_id
        }

        response = self._fetch(resource, params)

        return response

    def _fetch(self, resource, params):
        """Fetch a resource.

        :param resource: resource to get
        :param params: dict with the HTTP parameters needed to get
            the given resource
        """
        url = self.URL % {'resource' : resource}
        params[self.PTOKEN] = self.api_token

        logger.debug("Slack client requests: %s params: %s",
                     resource, str(params))

        r = requests.get(url, params=params)
        r.raise_for_status()

        # Check for possible API errors
        result = r.json()

        if not result['ok']:
            raise SlackClientError(error=result['error'])

        return r.text
