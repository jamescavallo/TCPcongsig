import argparse
import requests
import sys
import time


def main(query):
    r = requests.get(f'http://locate.measurementlab.net/v2/nearest/ndt/ndt7?{query}')
    d = r.json()
    machines = []
    xurls = []
    for sd in d['results']:
        if args.debug:
            print(f"country {sd['location']['country']} {sd['machine']}")
        machines.append(sd['machine'])
        for url in sd['urls']:
            if url.startswith('wss'):
                xurls.append(sd['urls'][url])

    if len(machines) > 0:
        print('#', ' '.join(machines))
    for url in xurls[:args.max]:
        print(f'$HOME/go/bin/ndt7-client -format json -service-url {url}')
    return len(xurls) > 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--region', default='', help='Specify region for NDT server query')
    parser.add_argument('-c', '--country', default='', help='Specify country for NDT server query')
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='Dump debugging information')
    parser.add_argument('-m', '--max', type=int, default=4, help='Max number of targets to use')
    args = parser.parse_args()
    
    if args.region != '':
        query = f'region={args.region}'
        #args.country = args.region.split('-')[0]
    elif args.country != '':
        query = f'country={args.country}'
    else:
        query = f'region=US-NY'
        #args.country = 'US'
    
    while not main(query):
        time.sleep(1)
