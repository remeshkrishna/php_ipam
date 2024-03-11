import requests

class Netbox:
    url = '' 
    api_token = ""
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Token ' + api_token
    }

    def __init__(self, url, api_token):
        self.url = url
        self.api_token = api_token

    def get_sites(self):
        result = requests.get(self.url + '/api/dcim/sites/', headers=self.headers)
        if result.status_code < 299:
            return result.json()
        else:
            return None

    def get_vrfs(self):
        result = requests.get(self.url + '/api/ipam/vrfs/', headers=self.headers)
        if result.status_code < 299:
            return result.json()['results']
        else:
            return None

    def create_prefix(self, site_id, prefix, description, vrf):
        data = {
            'prefix': prefix,
            'site': site_id,
            'description': description,
            'vrf': vrf
        }
        result = requests.post(self.url + '/api/ipam/prefixes/', json=data, headers=self.headers)
        if result.status_code < 299:
            print(vrf, site_id)
            return result.json()
        else:
            return None

    def create_address(self, address, dns_name, description, vrf = None):
        data = {
            'address': address,
            'dns_name': dns_name,
            'description': description,
            'vrf': int(vrf) if vrf is not None else None
        }
        result = requests.post(self.url + '/api/ipam/ip-addresses/', data=data, headers=self.headers)
        if result.status_code < 299:
            return result.json()
        else:
            return None

    def get_all_ip_addresses(self):
        output = []
        result = requests.get(self.url + '/api/ipam/ip-addresses/', headers=self.headers)
        if result.status_code < 299:
            while result.json()['next'] is not None:
                output.extend(result.json()['results'])
                result = requests.get(result.json()['next'], headers=self.headers)
            return output
        else:
            print(result.text)
            return None

    def update_ip(self, id):
        data = [{
            'id': id,
            'vrf': 1

        }]
        result = requests.patch(self.url + '/api/ipam/ip-addresses/', json=data, headers=self.headers)
        if result.status_code < 299:
            return result.json()
        else:
            print(result.text)
            return None
