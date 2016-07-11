from urlparse import urljoin 
import os
import requests
import re

from scrapy.utils.python import unique as unique_list, str_to_unicode
from BeautifulSoup import BeautifulSoup

def apply_reg_ex_to_urls(regex, url_list):
    regex = re.compile('(' + regex + ')')
    matches = [m.group(1) for l in url_list for m in [regex.search(l)] if m]
    return matches

def get_urls(_url, _html=None, headers=None):
    if _html is None: 
        response = requests.get(_url, verify=False, headers=headers)
        _html = response.content
    page = str(BeautifulSoup(_html))
    url_list = []
    while True:
        url, n = get_url(page)
        page = page[n:]
        if url:
            url = urljoin(_url, url)
            url_list.append(url)
        else:
            break
    url_list = unique_list(url_list)
    return url_list
    
def get_url(page):
    start_link = page.find("href")
    if start_link == -1:
        return None, 0
    start_quote = page.find('"', start_link)
    end_quote = page.find('"', start_quote + 1)
    url = page[start_quote + 1: end_quote]
    return url, end_quote
