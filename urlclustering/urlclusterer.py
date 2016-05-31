from __future__ import unicode_literals
import re
from collections import defaultdict
from urlclustering.urltree import URLTreeNode
from urlclustering.parsedurl import ParsedURL
from urlparse import urlparse
from collections import namedtuple
from scrapy.utils.python import unique as unique_list

"""
This package facilitates the clustering of similar URLs.

How it works:
-------------
URLs are grouped using two different methods - 
 1. signature of path parts
 2. similar domain parts (ie. x.craigslist.org, y.craigslist.org => [...].craigslist.org) 
The resulting two clusters are then merged. 

Description of the 1st method (signatures): 
URLs are grouped by a signature which is the number of path elements
and the number of QueryString parameters & values the URL has.
Examples:
http://ex.com/about has a signature of (1, 0)
http://ex.com/article?123 has a signature of (1, 1)
http://ex.com/path/to/file?par1=val1&par2=val2 has a signature of (3, 4)

URLs with the same signature are inserted in a tree structure. For
each part (path element or QS parameter or QS value) two nodes are created:
- One with the verbatim part.
- One with the reduced part i.e. a regex that could replace the part.
Leaf nodes hold the number of URLs that match and the number of reductions.

E.g. inserting URL `http://ex.com/article?123` will create 2 top nodes:
    root 1: `article`
    root 2: `[^/]+`
And each top node will have two children:
    child 1: `123`
    child 2: `\d+`
Inserting 3 URLs of the form `/article/[0-9]+` would lead to a tree like this:

           `article`                        `[^/]+`
      /    /      \     \             /    /      \     \
  `123`  `456`  `789`  `\d+`      `123`  `456`  `789`  `\d+`
  1 URL  1 URL  1 URL  3 URLs     1 URL  1 URL  1 URL  3 URLs
  0 re   0 re   0 re   1 re       1 re   1 re   1 re   2  re

The final step is to choose the best leafs. In this case `article` -> `\d+`
is best because it macthes all 3 URLs with 1 reduction so the cluster returned
is http://ex.com/article?(\d+)

Description of the 2nd method (similar domains): 
TODO
"""
def _cluster_same_signature_urls(parsed_urls, min_cluster_size):
    """
    Returns patterns matching >=min_cluster_size urls in best -> worst order.
    List of URLs must have the same signature (path + QS elements).
    """
    patterns = []
    if len(parsed_urls) == 0:
        return patterns
    max_reductions = len(parsed_urls[0].parts)

    # build our URL tree
    root = URLTreeNode()
    for parsed in parsed_urls:
        root.add_url(parsed)

    # reduce leafs by removing the best one at each iteration and 
    # removing those that fall below the min cluster size
    leafs = root.leafs()
    for leaf in leafs:
        if len(leaf['urls']) < min_cluster_size:
            leafs.remove(leaf)
    
    while leafs:
        bestleaf = max(
            leafs,
            key=lambda x:
#                len(x['urls']) * (1 if (max_reductions - x['reductions']) == 0 else max_reductions - x['reductions']) ** 2
                len(x['urls']) * (max_reductions - x['reductions']) ** 2
        )
        if len(bestleaf['urls']) >= min_cluster_size:
            patterns.append((bestleaf['pattern'],
                             bestleaf['h_pattern']))
        leafs.remove(bestleaf)
        remaining_leafs = []
        for leaf in leafs:
            leaf['urls'] -= bestleaf['urls']
            if leaf['urls']:
                remaining_leafs.append(leaf)
        leafs = remaining_leafs

    return patterns

def _cluster_same_domain_urls(parsed_urls, min_cluster_size):
    """Returns clusters and a list of unclustered urls."""

    # group URLs by signature
    url_map = defaultdict(list)
    for parsed in parsed_urls:
        url_map[parsed.signature].append(parsed)

    # build clusters
    clusters = defaultdict(list)
    unclustered = []
    for parsed_urls in url_map.values():
        if len(parsed_urls) < min_cluster_size:
            unclustered.extend([x.url for x in parsed_urls])
            continue
        patterns = _cluster_same_signature_urls(parsed_urls, min_cluster_size)
        for (pattern, h_pattern) in patterns:
            remaining_urls = []
            # add matching URLs to cluster and remove from remaining URLs
            for parsed in parsed_urls:
                if re.search(pattern, parsed.url):
                    clusters[(pattern, h_pattern)].append(parsed.url)
                else:
                    remaining_urls.append(parsed)
            parsed_urls = remaining_urls

        # everything left goes to unclustered
        unclustered.extend(x.url for x in parsed_urls)

    return {'clusters': clusters, 'unclustered': unclustered}

def _cluster_similar_domain_urls(parsed_urls, min_cluster_size):
    """Returns clusters and a list of unclustered urls."""

    DomainPart = namedtuple("DomainPart", ["part", "loc", "dsize", "scheme"])
    domain_map = defaultdict(list)

    unclustered_urls = []
    unclustered_urls.extend(x.url for x in parsed_urls)

    #group each unique part across all URLs
    for parsed in parsed_urls:
        try:             
            url = urlparse(parsed.domain)
            domain_parts = url.netloc.split('.')
            scheme = url.scheme
        except: 
            continue
        for i in range(len(domain_parts)):
            domain_part = DomainPart(part=domain_parts[i],loc=i,dsize=len(domain_parts), scheme=scheme)            
            domain_map[domain_part].append(parsed)

    #remove any groups below the minimum cluster size, sort remaining w/ largest group first
    clusterables = defaultdict(list)
    for domain_part in domain_map.keys():
        if len(domain_map[domain_part]) >= min_cluster_size:
            clusterables[domain_part] = len(domain_map[domain_part])
    clusterables = sorted(clusterables, key=clusterables.__getitem__, reverse=True)
    
    #build most flexible regex for each domain part group, create cluster w/ urls and updated unclustered_urls
    clusters=[]
    for domain_part in clusterables:
        url = urlparse(domain_map[domain_part][0].domain)
        domain = url.netloc.split('.')
        _regex = []
        for i in range(len(domain)):
            _regex.append('([^/]+)' if i != int(domain_part.loc) else domain[i])
        urls = []
        for parsed in domain_map[domain_part]:
            urls.append(parsed.url)
            try: 
                unclustered_urls.remove(parsed.url)
            except:
                continue
        regex = domain_part.scheme + '://'
        regex += '.'.join(map(str, _regex))
        cluster = {"regex": regex, "human": regex, "urls": urls}
        clusters.append(cluster)

    #reduce regex components in each cluster where appropriate    
    for cluster in clusters:
        for cluster2 in clusters: 
            if cluster != cluster2 and set(cluster['urls']) <= set(cluster2['urls']):
                cluster_r = cluster['regex'].split('.')
                cluster2_r = cluster2['regex'].split('.')                
                for i in range(len(cluster_r)): 
                    if '([^/]+)' in cluster_r[i] and '([^/]+)' not in cluster2_r[i]:
                        cluster_r[i] = cluster2_r[i]                        
                cluster['regex'] = '.'.join(map(str, cluster_r))

    #Remove duplicate clusters
    for cluster in clusters:
        for cluster2 in clusters:
            if cluster != cluster2 and cluster['regex'] == cluster2['regex'] and cluster['urls'] == cluster2['urls']:
                clusters.remove(cluster2)

    #Set human-readable regex and update unclustered_urls
    for cluster in clusters:
        cluster['human'] = cluster['regex'].replace('([^/]+)', '[...]')

    return {'clusters': clusters, 'unclustered': unclustered_urls}

#Merges same domain signature clusters w/ similar domain clusters, where appropriate
def merge_clusters(merged, all_urls, min_cluster_size):
    res = {'clusters': {}, 'unclustered': []}
    unclustered = all_urls
    for regex in merged:
        matches = apply_reg_ex_to_urls(regex, all_urls)
        matches = unique_list(matches)
        if len(matches) >= min_cluster_size:
            for match in matches: 
                try: 
                    unclustered.remove(match)
                except:
                    continue
            human = regex.replace('([^/]+)', '[...]').replace('([^&=?]+)', '[...]').replace('(\d+)', '[NUMBER]')
            res['clusters'].update({(regex, human): matches})
    res['unclustered'] = unclustered
    return res

def cluster_urls(urls, min_cluster_size=10):
    if min_cluster_size < 2:
        min_cluster_size = 2
    res = {'clusters': {}, 'unclustered': []}
    res2 = {'clusters': {}, 'unclustered': []}

    # get ParsedURL objects for each url
    parsed_urls = []
    all_parsed = []
    for url in urls:
        parsed = ParsedURL(url)
        parsed_urls.append(parsed)
        all_parsed.append(parsed)

    # group urls by domain
    by_domain = defaultdict(list)
    for parsed in parsed_urls:
        try:
            by_domain[parsed.domain].append(parsed)
        except:
            res['unclustered'].append(parsed.url)
            
    similar_domains = []    
    if len(by_domain) > 1:
        c_res = _cluster_similar_domain_urls(all_parsed, min_cluster_size)
        res2['unclustered'] = c_res['unclustered']
        res2['clusters'].update({(cluster['regex'],
                                  cluster['human']): cluster['urls']
                                  for cluster in c_res['clusters']})
        for cluster in c_res['clusters']: 
            similar_domains.append(cluster['regex'])
            
    # cluster in each domain group
    for domain, parsed_urls in by_domain.items():
        c_res = _cluster_same_domain_urls(parsed_urls, min_cluster_size)
        res['clusters'].update({('%s%s' % (domain, k[0]),
                                 '%s%s' % (domain, k[1])): v
                                for k, v in c_res['clusters'].items()})
        res['unclustered'].extend(c_res['unclustered'])
    r1 = []
    for k, v in c_res['clusters'].items():
        r1.append(k[0])
    
    if len(similar_domains) >= 1:
        merged = []
        merged.extend(similar_domains)
        for sd in similar_domains:
            for r_1 in r1: 
                merged.append('%s%s' %(sd, r_1))
    
        merged_clusters = merge_clusters(merged, urls, min_cluster_size)
        res['clusters'].update({('%s' % (k[0]),
                                 '%s' % (k[1])): v 
                                for k, v in merged_clusters['clusters'].items()})
    return res

def apply_reg_ex_to_urls(regex, url_list):
    regex = re.compile('(' + regex + ')')
    matches = [m.group(1) for l in url_list for m in [regex.search(l)] if m]
    return matches
