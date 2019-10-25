# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2019 Bitergia
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
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#     Aaron Nickovich <aaronnickovich@gmail.com>
#

import json
import logging
import random
import re

from requests.utils import quote

from grimoirelab_toolkit.datetime import (datetime_to_utc,
                                          datetime_utcnow,
                                          str_to_datetime)
from grimoirelab_toolkit.uris import urijoin

from ...backend import (Backend,
                        BackendCommand,
                        BackendCommandArgumentParser,
                        DEFAULT_SEARCH_FIELD)
from ...client import HttpClient, RateLimitHandler
from ...utils import DEFAULT_DATETIME, DEFAULT_LAST_DATETIME

CATEGORY_ISSUE = "issue"
CATEGORY_PULL_REQUEST = "pull_request"
CATEGORY_REPO = "repository"

BITBUCKET_URL = "https://bitbucket.org"
BITBUCKET_API_URL = "https://api.bitbucket.org/"

# Range before sleeping until rate limit reset
MIN_RATE_LIMIT = 10
MAX_RATE_LIMIT = 500

MAX_CATEGORY_ITEMS_PER_PAGE = 50
PER_PAGE = 50

# Default sleep time and retries to deal with connection/server problems
DEFAULT_SLEEP_TIME = 1
MAX_RETRIES = 5

TARGET_ISSUE_FIELDS = ['reporter', 'assignee']
TARGET_PULL_FIELDS = ['author', 'closed_by', 'participants']

logger = logging.getLogger(__name__)


class BitBucketv2(Backend):
    """BitBucket backend for Perceval.

    This class allows the fetch the issues stored in BitBucket
    repository. Note that since version 0.20.0, the `api_token` accepts
    a list of tokens, thus the backend must be initialized as follows:
    ```
    BitBucketv2(
        owner='chaoss', repository='grimoirelab',
        api_token=[TOKEN-1, TOKEN-2, ...], sleep_for_rate=True,
        sleep_time=300
    )
    ```

    :param owner: BitBucket owner
    :param repository: BitBucket repository from the owner
    :param api_token: list of BitBucket auth tokens to access the API
    :param base_url: BitBucket URL in enterprise edition case;
        when no value is set the backend will be fetch the data
        from the BitBucket public site.
    :param tag: label used to mark the data
    :param archive: archive to store/retrieve items
    :param sleep_for_rate: sleep until rate limit is reset
    :param min_rate_to_sleep: minimun rate needed to sleep until
         it will be reset
    :param max_retries: number of max retries to a data source
        before raising a RetryError exception
    :param max_items: max number of category items (e.g., issues,
        pull requests) per query
    :param sleep_time: time to sleep in case
        of connection problems
    """
    version = '0.1.0'

    CATEGORIES = [CATEGORY_ISSUE, CATEGORY_PULL_REQUEST, CATEGORY_REPO]

    def __init__(self, owner=None, repository=None,
                 api_token=None, base_url=None,
                 tag=None, archive=None,
                 sleep_for_rate=False, min_rate_to_sleep=MIN_RATE_LIMIT,
                 max_retries=MAX_RETRIES, sleep_time=DEFAULT_SLEEP_TIME,
                 max_items=MAX_CATEGORY_ITEMS_PER_PAGE):
        if api_token is None:
            api_token = []

        origin = base_url if base_url else BITBUCKET_URL
        origin = urijoin(origin, owner, repository)

        super().__init__(origin, tag=tag, archive=archive)

        self.owner = owner
        self.repository = repository
        self.api_token = api_token
        self.base_url = base_url

        self.sleep_for_rate = sleep_for_rate
        self.min_rate_to_sleep = min_rate_to_sleep
        self.max_retries = max_retries
        self.sleep_time = sleep_time
        self.max_items = max_items

        self.client = None
        self._users = {}  # internal users cache

    def search_fields(self, item):
        """Add search fields to an item.

        It adds the values of `metadata_id` plus the `owner` and `repo`.

        :param item: the item to extract the search fields values

        :returns: a dict of search fields
        """
        search_fields = {
            DEFAULT_SEARCH_FIELD: self.metadata_id(item),
            'owner': self.owner,
            'repo': self.repository
        }

        return search_fields

    def fetch(self, category=CATEGORY_PULL_REQUEST, from_date=DEFAULT_DATETIME, to_date=DEFAULT_LAST_DATETIME):
        """Fetch the issues/pull requests from the repository.

        The method retrieves, from a BitBucket repository, the issues/pull requests
        updated since the given date.

        :param category: the category of items to fetch
        :param from_date: obtain issues/pull requests updated since this date
        :param to_date: obtain issues/pull requests until a specific date (included)

        :returns: a generator of issues
        """
        if not from_date:
            from_date = DEFAULT_DATETIME
        if not to_date:
            to_date = DEFAULT_LAST_DATETIME

        from_date = datetime_to_utc(from_date)
        to_date = datetime_to_utc(to_date)

        kwargs = {
            'from_date': from_date,
            'to_date': to_date
        }
        items = super().fetch(category, **kwargs)

        return items

    def fetch_items(self, category, **kwargs):
        """Fetch the items (issues or pull_requests)

        :param category: the category of items to fetch
        :param kwargs: backend arguments

        :returns: a generator of items
        """
        from_date = kwargs['from_date']
        to_date = kwargs['to_date']

        if category == CATEGORY_ISSUE:
            items = self.__fetch_issues(from_date, to_date)
        elif category == CATEGORY_PULL_REQUEST:
            items = self.__fetch_pull_requests(from_date, to_date)
        else:
            items = self.__fetch_repo_info()

        return items

    @classmethod
    def has_archiving(cls):
        """Returns whether it supports archiving items on the fetch process.

        :returns: this backend supports items archive
        """
        return True

    @classmethod
    def has_resuming(cls):
        """Returns whether it supports to resume the fetch process.

        :returns: this backend supports items resuming
        """
        return True

    @staticmethod
    def metadata_id(item):
        """Extracts the identifier from a BitBucket item."""

        # works for both API 1.0 and 2.0
        return str(item['id'])

    @staticmethod
    def metadata_updated_on(item):
        """Extracts the update time from a BitBucket item.

        The timestamp used is extracted from 'updated_on' field.
        This date is converted to UNIX timestamp format. As BitBucket
        dates are in UTC the conversion is straightforward.

        :param item: item generated by the backend

        :returns: a UNIX timestamp
        """

        if "updated_on" in item:
            ts = item['updated_on']
            ts = str_to_datetime(ts)

            return ts.timestamp()

    @staticmethod
    def metadata_category(item):
        """Extracts the category from a BitBucket item.

        This backend generates two types of item which are
        'repo' and 'pull_request'.
        """

        # works for both API 1.0 and 2.0
        if "votes" in item:
            category = CATEGORY_ISSUE
        elif "reviewers" in item:
            category = CATEGORY_PULL_REQUEST
        else:
            category = CATEGORY_REPO

        return category

    def _init_client(self, from_archive=False):
        """Init client"""

        return BitBucketClientv2(self.owner, self.repository, self.api_token, self.base_url,
                                 self.sleep_for_rate, self.min_rate_to_sleep,
                                 self.sleep_time, self.max_retries, self.max_items,
                                 self.archive, from_archive)

    def __fetch_issues(self, from_date, to_date):
        """Fetch the issues"""

        issues_groups = self.client.issues(from_date=from_date, to_date=to_date)

        for raw_issues in issues_groups:
            issues = json.loads(raw_issues)
            for issue in issues['values']:

                issue['comments_data'] = self.__get_issue_comments(issue['id'], from_date, to_date)

                self.__init_extra_issue_fields(issue)
                for field in TARGET_ISSUE_FIELDS:

                    if not issue[field]:
                        continue

                    if (field == 'reporter' or field == 'assignee') and issue[field] and 'type' in issue[field]:
                        user_type = issue[field]['type']
                        issue[field + '_data'] = self.__get_user(issue[field]['uuid'], user_type)

                yield issue

    def __fetch_pull_requests(self, from_date, to_date):
        """Fetch the pull requests"""

        raw_pulls = self.client.pulls(from_date, to_date)

        for raw_pull in raw_pulls:
            pulls = json.loads(raw_pull)
            for pull in pulls['values']:

                compare_time = str_to_datetime(pull['updated_on'])

                if to_date < compare_time < from_date:
                    return

                self.__init_extra_pull_fields(pull)

                pull['commits_data'] = self.__get_pull_commits(pull['id'], from_date, to_date)

                if pull['comment_count'] > 0:
                    pull['comments_data'] = self.__get_pull_comments(pull['id'], from_date, to_date)

                for field in TARGET_PULL_FIELDS:
                    if not field in pull:
                        continue

                    if (field == 'author' or field == 'closed_by') and pull[field] and 'type' in pull[field]:
                        user_type = pull[field]['type']
                        pull[user_type] = self.__get_user(pull[field]['uuid'], user_type)
                    elif field == 'participants':
                        pull[field + '_data'] = self.__get_participants(pull[field])

                yield pull

    def __fetch_repo_info(self):
        """Get repo info about stars, watchers and forks"""

        raw_repo = self.client.repo()
        repo = json.loads(raw_repo)

        fetched_on = datetime_utcnow()
        repo['fetched_on'] = fetched_on.timestamp()

        yield repo

    def __get_issue_comments(self, issue_number, from_date, to_date):
        """Get issue comments"""

        comments_list = []
        group_comments = self.client.issue_comments(issue_number, from_date, to_date)

        for raw_comments in group_comments:

            comments = json.loads(raw_comments)
            for comment in comments['values']:

                if 'user' in comment and comment['user'] and 'type' in comment['user']:
                    user_type = comment['user']['type']
                    comment[user_type + '_data'] = self.__get_user(comment['user']['uuid'], user_type)
                    comments_list.append(comment)

        return comments_list

    def __get_pull_commits(self, pr_number, from_date, to_date):
        """Get pull request commit hashes"""

        hashes = []
        group_pull_commits = self.client.pull_commits(pr_number, from_date, to_date)

        for raw_pull_commits in group_pull_commits:
            group_pull_commits = json.loads(raw_pull_commits)

            for commit in group_pull_commits['values']:

                #TODO: Do I add user info to the commit info?
                #if 'author' in commit and commit['author'] and 'type' in commit['author']:
                #    user_type = commit['author']['type']
                #    self.__get_user(commit['author']['uuid'], user_type)
                #
                #if 'committer' in commit and commit['committer'] and 'type' in commit['committer']:
                #    user_type = commit['committer']['type']
                #    self.__get_user(commit['committer']['uuid'], user_type)

                commit_hash = commit['hash']
                hashes.append(commit_hash)
            return hashes

    def __get_pull_comments(self, pr_number, from_date, to_date):

        comments = []
        group_pull_comments = self.client.pull_comments(pr_number, from_date, to_date)

        for raw_pull_comments in group_pull_comments:
            group_pull_comments = json.loads(raw_pull_comments)

            for comment in group_pull_comments['values']:

                if "pullrequest" not in comment:
                    continue

                if 'user' in comment and comment['user'] and 'type' in comment['user']:
                    user_type = comment['user']['type']
                    comment[user_type + '_data'] = self.__get_user(comment['user']['uuid'], user_type)

                comments.append(comment)

            return comments

    def __get_user(self, login, user_type):
        """Get user and org data for the login"""

        user = None

        if not login:
            return user

        # quote will urlencodes the user ID to match bitbucket's API:
        # if user's uuid includes '{' or '}', they are converted to %7B and %7D
        encoded_login = quote(login)

        user_raw = self.client.user(encoded_login, user_type)
        user = json.loads(user_raw)
        user['login'] = encoded_login

        return user

    def __get_participants(self, users):
        """Find user info on each participants"""

        participants = []

        if not users:
            return participants

        for user in users:
            if 'user' in user and user['user'] and 'type' in user['user']:
                user_type = user['user']['type']
                user[user_type + '_data'] = self.__get_user(user['user']['uuid'], user_type)

            participants.append(user)

        return participants

    def __init_extra_issue_fields(self, issue):
        """Add fields to an issue"""

        issue['reporter_data'] = {}
        issue['assignee_data'] = {}
        issue['comments_data'] = []

    def __init_extra_pull_fields(self, pull):
        """Add fields to a pull request"""

        pull['author_data'] = {}
        pull['closed_by_data'] = {}
        pull['commits_data'] = []
        pull['comments_data'] = []
        pull['participants_data'] = []

class BitBucketClientv2(HttpClient, RateLimitHandler):
    """Client for retieving information from BitBucket API

    :param owner: BitBucket owner
    :param repository: BitBucket repository from the owner
    :param tokens: list of BitBucket auth tokens to access the API
    :param base_url: BitBucket URL in enterprise edition case;
        when no value is set the backend will be fetch the data
        from the BitBucket public site.
    :param sleep_for_rate: sleep until rate limit is reset
    :param min_rate_to_sleep: minimun rate needed to sleep until
         it will be reset
    :param sleep_time: time to sleep in case
        of connection problems
    :param max_retries: number of max retries to a data source
        before raising a RetryError exception
    :param max_items: max number of category items (e.g., issues,
        pull requests) per query
    :param archive: collect issues already retrieved from an archive
    :param from_archive: it tells whether to write/read the archive
    """
    EXTRA_STATUS_FORCELIST = [403, 500, 502, 503]

    _users = {}       # users cache
    _teams = {}       # teams cache

    def __init__(self, owner, repository, tokens,
                 base_url=None, sleep_for_rate=False, min_rate_to_sleep=MIN_RATE_LIMIT,
                 sleep_time=DEFAULT_SLEEP_TIME, max_retries=MAX_RETRIES,
                 max_items=MAX_CATEGORY_ITEMS_PER_PAGE, archive=None, from_archive=False):
        self.owner = owner
        self.repository = repository
        self.tokens = tokens
        self.n_tokens = len(self.tokens)
        self.current_token = None
        self.last_rate_limit_checked = None
        self.max_items = max_items

        if base_url:
            base_url = urijoin(base_url, 'api', 2.0)
        else:
            base_url = urijoin(BITBUCKET_API_URL, 2.0)

        super().__init__(base_url, sleep_time=sleep_time, max_retries=max_retries,
                         extra_status_forcelist=self.EXTRA_STATUS_FORCELIST,
                         archive=archive, from_archive=from_archive)
        super().setup_rate_limit_handler(sleep_for_rate=sleep_for_rate, min_rate_to_sleep=min_rate_to_sleep)

        # Choose best API token (randomly)
        if not self.from_archive:
            self._rand_next_api_token()

    def calculate_time_to_reset(self):
        """Calculate the seconds to reset the token requests, by obtaining the different
        between the current date and the next date when the token is fully regenerated.
        """

        time_to_reset = self.rate_limit_reset_ts - (datetime_utcnow().replace(microsecond=0).timestamp() + 1)
        time_to_reset = 0 if time_to_reset < 0 else time_to_reset

        return time_to_reset

    @staticmethod
    def sanitize_for_archive(url, headers, payload):
        """Sanitize payload of a HTTP request by removing the token information
        before storing/retrieving archived items

        :param: url: HTTP url request
        :param: headers: HTTP headers request
        :param: payload: HTTP payload request

        :returns url, headers and the sanitized payload
        """
        if not headers:
            return url, headers, payload

        if 'Authorization' in headers:
            headers.pop('Authorization', None)

        return url, headers, payload

    def issues(self, from_date=None, to_date=None):
        """Fetch the pull requests from the repository.

        The method retrieves, from a BitBucket repository, the pull requests
         from a v1 bitbucket server.

        :returns: a generator of pull requests
        """

        # ?sort=-updated_on&state=ALL&q=updated_on>=2014-03-26T13:15:00.000000+AND+updated_on<=2017-08-26T13:15:00.000000

        payload = {
            'sort': '-updated_on',
            'state': 'ALL',
            'pagelen': self.max_items}

        tmp_from_date = re.sub('(\+.*)?', '', str(from_date)).replace(" ", "T")
        tmp_to_date = re.sub('(\+.*)?', '', str(to_date)).replace(" ", "T")

        if from_date and to_date:
            if from_date < to_date:
                payload['q'] = 'updated_on>=' + tmp_from_date + '+AND+updated_on<=' + tmp_to_date
            else:
                logger.warning("from_date is set to a later datetime than to_date: %s > %s",
                               (tmp_from_date, tmp_to_date))
                return
        elif from_date:
            payload['q'] = 'updated_on>=' + tmp_from_date
        elif to_date:
            payload['q'] = 'updated_on<=' + tmp_to_date

        payload_str = "&".join("%s=%s" % (k, v) for k, v in payload.items())

        path = urijoin("issues")
        return self.fetch_items(path, payload_str)

    def pulls(self, from_date=None, to_date=None):
        """Fetch the pull requests from the repository.

        The method retrieves, from a BitBucket repository, the pull requests
         from a v1 bitbucket server.

        :returns: a generator of pull requests
        """

        # ?sort=-updated_on&state=ALL&q=updated_on>=2014-03-26T13:15:00.000000+AND+updated_on<=2017-08-26T13:15:00.000000

        payload = {
            'sort': '-updated_on',
            'state': 'ALL',
            'pagelen': self.max_items}

        tmp_from_date = re.sub('(\+.*)?', '', str(from_date)).replace(" ", "T")
        tmp_to_date = re.sub('(\+.*)?', '', str(to_date)).replace(" ", "T")

        if from_date and to_date:
            if from_date < to_date:
                payload['q'] = 'updated_on>=' + tmp_from_date + '+AND+updated_on<=' + tmp_to_date
            else:
                logger.warning("from_date is set to a later datetime than to_date: %s > %s",
                               (tmp_from_date, tmp_to_date))
                return
        elif from_date:
            payload['q'] = 'updated_on>=' + tmp_from_date
        elif to_date:
            payload['q'] = 'updated_on<=' + tmp_to_date

        payload_str = "&".join("%s=%s" % (k, v) for k, v in payload.items())

        path = urijoin("pullrequests")
        return self.fetch_items(path, payload_str)

    def repo(self):
        """Get repository data"""

        path = urijoin(self.base_url, 'repositories', self.owner, self.repository)

        r = self.fetch(path)
        repo = r.text

        return repo

    def pull_commits(self, pr_number, from_date, to_date):
        """Get pull request commits"""

        # ?sort=-updated_on&state=ALL&q=updated_on>=2014-03-26T13:15:00.000000+AND+updated_on<=2017-08-26T13:15:00.000000
        payload = {
            'sort': '-date',
            'state': 'ALL',
            'pagelen': self.max_items}

        tmp_from_date = re.sub('(\+.*)?', '', str(from_date)).replace(" ", "T")
        tmp_to_date = re.sub('(\+.*)?', '', str(to_date)).replace(" ", "T")

        if from_date and to_date:
            if from_date < to_date:
                payload['q'] = 'date>=' + tmp_from_date + '+AND+date<=' + tmp_to_date
            else:
                logger.warning("from_date is set to a later datetime than to_date: %s > %s",
                               (tmp_from_date, tmp_to_date))
                return
        elif from_date:
            payload['q'] = 'date>=' + tmp_from_date
        elif to_date:
            payload['q'] = 'date<=' + tmp_to_date

        payload_str = "&".join("%s=%s" % (k, v) for k, v in payload.items())

        commit_url = urijoin("pullrequests", str(pr_number), "commits")
        return self.fetch_items_pull_commits(commit_url, payload_str)

    def pull_comments(self, pr_number, from_date, to_date):
        """Get pull request review comments"""

        payload = {
            'sort': '-created_on',
            'state': 'ALL',
            'pagelen': self.max_items}

        tmp_from_date = re.sub('(\+.*)?', '', str(from_date)).replace(" ", "T")
        tmp_to_date = re.sub('(\+.*)?', '', str(to_date)).replace(" ", "T")

        if from_date and to_date:
            if from_date < to_date:
                payload['q'] = 'created_on>=' + tmp_from_date + '+AND+created_on<=' + tmp_to_date
            else:
                logger.warning("from_date is set to a later datetime than to_date: %s > %s",
                               (tmp_from_date, tmp_to_date))
                return
        elif from_date:
            payload['q'] = 'created_on>=' + tmp_from_date
        elif to_date:
            payload['q'] = 'created_on<=' + tmp_to_date

        payload_str = "&".join("%s=%s" % (k, v) for k, v in payload.items())

        comments_url = urijoin("pullrequests", str(pr_number), "comments")
        return self.fetch_items(comments_url, payload_str)

    def issue_comments(self, issue_number, from_date, to_date):
        """Get issue comments"""

        payload = {
            'sort': '-created_on',
            'state': 'ALL',
            'pagelen': self.max_items}

        tmp_from_date = re.sub('(\+.*)?', '', str(from_date)).replace(" ", "T")
        tmp_to_date = re.sub('(\+.*)?', '', str(to_date)).replace(" ", "T")

        if from_date and to_date:
            if from_date < to_date:
                payload['q'] = 'created_on>=' + tmp_from_date + '+AND+created_on<=' + tmp_to_date
            else:
                logger.warning("from_date is set to a later datetime than to_date: %s > %s",
                               (tmp_from_date, tmp_to_date))
                return
        elif from_date:
            payload['q'] = 'created_on>=' + tmp_from_date
        elif to_date:
            payload['q'] = 'created_on<=' + tmp_to_date

        payload_str = "&".join("%s=%s" % (k, v) for k, v in payload.items())

        comments_url = urijoin("issues", str(issue_number), "comments")
        return self.fetch_items(comments_url, payload_str)

    def user(self, login, user_type):
        """Get the user information and update the user cache"""
        user = None

        if login in self._users:
            return self._users[login]

        if user_type == "user":
            url_user = urijoin(self.base_url, 'users', login)
        elif user_type == "team":
            url_user = urijoin(self.base_url, 'teams', login)

        logging.info("Getting info for %s" % (url_user))

        r = self.fetch(url_user)
        user = r.text
        self._users[login] = user

        return user

    def team(self, login):
        """Get the team information and update the team cache"""
        team = None

        if login in self._teams:
            return self._teams[login]

        url_team = urijoin(self.base_url, 'teams', login)

        logging.info("Getting info for %s" % (url_team))

        r = self.fetch(url_team)
        team = r.text
        self._teams[login] = team

        return team

    def fetch(self, url, payload=None, headers=None, method=HttpClient.GET, stream=False, verify=True):
        """Fetch the data from a given URL.

        :param url: link to the resource
        :param payload: payload of the request
        :param headers: headers of the request
        :param method: type of request call (GET or POST)
        :param stream: defer downloading the response body until the response content is available

        :returns a response object
        """
        if not self.from_archive:
            self.sleep_for_rate_limit()

        response = super().fetch(url, payload, headers, method, stream, verify)

        if not self.from_archive:
            self._rand_next_api_token()

        return response

    def fetch_items_pull_commits(self, path, payload):
        """Return the items from bitbucket API using links pagination"""

        page = 0  # current page

        url_next = urijoin(self.base_url, 'repositories', self.owner, self.repository, path)
        logger.debug("Get BitBucket paginated items from " + url_next)

        #handle a 404 error where the resources may not be available or missing
        try:
            response = self.fetch(url_next, payload=payload)
        except:
            yield '{"values":[]}'
        else:

            items = response.text
            page += 1

            while items:
                yield items

                items = None

                response_json = json.loads(response.text)
                if 'next' in response_json:
                    url_next = response_json['next']

                    response = self.fetch(url_next)

                    page += 1

                    items = response.text
                    logger.debug("Page: %i" % (page))

    def fetch_items(self, path, payload):
        """Return the items from bitbucket API using links pagination"""

        page = 0  # current page

        url_next = urijoin(self.base_url, 'repositories', self.owner, self.repository, path)
        logger.debug("Get BitBucket paginated items from " + url_next)

        response = self.fetch(url_next, payload=payload)

        items = response.text
        page += 1

        while items:
            yield items

            items = None

            response_json = json.loads(response.text)
            if 'next' in response_json:
                url_next = response_json['next']

                response = self.fetch(url_next)

                page += 1

                items = response.text
                logger.debug("Page: %i" % (page))

    #TODO: rate-limit is mentioned, but not clear how it actually works. How to test public bitbucket.org? Select random token for now...
    def _rand_next_api_token(self):
        """Check all API tokens defined and choose one with most remaining API points"""

        # Return if no tokens given
        if self.n_tokens == 0:
            return

        # If multiple tokens given, choose best
        token_idx = 0
        if self.n_tokens > 1:
            token_idx = random.randint(0, self.n_tokens-1)
            logger.debug("Choosen token index: {}".format(token_idx))

        # If we have any tokens - use best of them
        self.current_token = self.tokens[token_idx]
        self.session.headers.update({'Authorization': 'Bearer ' + self.current_token})

class BitBucketCommandv2(BackendCommand):
    """Class to run BitBucket backend from the command line."""

    BACKEND = BitBucketv2

    @classmethod
    def setup_cmd_parser(cls):
        """Returns the BitBucket argument parser."""

        parser = BackendCommandArgumentParser(cls.BACKEND,
                                              from_date=True,
                                              to_date=True,
                                              token_auth=False,
                                              archive=True)
        # BitBucket options
        group = parser.parser.add_argument_group('BitBucket arguments')
        group.add_argument('--enterprise-url', dest='base_url',
                           help="Base URL for BitBucket Enterprise instance")
        group.add_argument('--sleep-for-rate', dest='sleep_for_rate',
                           action='store_true',
                           help="sleep for getting more rate")
        group.add_argument('--min-rate-to-sleep', dest='min_rate_to_sleep',
                           default=MIN_RATE_LIMIT, type=int,
                           help="sleep until reset when the rate limit reaches this value")
        # BitBucket token(s)
        group.add_argument('-t', '--api-token', dest='api_token',
                           nargs='+',
                           default=[],
                           help="list of BitBucket API tokens")

        # Generic client options
        group.add_argument('--max-items', dest='max_items',
                           default=MAX_CATEGORY_ITEMS_PER_PAGE, type=int,
                           help="Max number of items per page per query.")
        group.add_argument('--max-retries', dest='max_retries',
                           default=MAX_RETRIES, type=int,
                           help="number of API call retries")
        group.add_argument('--sleep-time', dest='sleep_time',
                           default=DEFAULT_SLEEP_TIME, type=int,
                           help="sleeping time between API call retries")

        # Positional arguments
        parser.parser.add_argument('owner',
                                   help="BitBucket owner")
        parser.parser.add_argument('repository',
                                   help="BitBucket repository")

        return parser
