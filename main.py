import json
import struct
import socket
import inspect
import logging
import requests
from requests.auth import HTTPBasicAuth
# import re
import sys
requests.packages.urllib3.disable_warnings()
logger = logging.getLogger(__name__)
phpipam_obj = {
        'server': 'url',
        'app_id': 'app',
        'username': 'user',
        'password': 'password'
}

class phpIPAM(object):
    """An interface to phpIPAM web API."""

    def __init__(self, server, app_id, username, password, ssl_verify=True, debug=False):
        """Parameters:
        server: the base server location.
        app_id: the app ID to access
        username: username
        password: password
        ssl_verify: should the certificate being verified"""
        self.error = 0
        self.error_message = ""
        self.server = server
        self.app_id = app_id
        self.username = username
        self.password = password
        self.appbase = "%s/api/%s" % (self.server, self.app_id)
        self.ssl_verify = ssl_verify
        self.token = None
        if debug:
            self.enable_debug()
        self.login()

    def enable_debug(self):
        try:
            import http.client as http_client
        except ImportError:
            # Python 2
            import httplib as http_client
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    def __query(self, entrypoint, method=requests.get, data=None, auth=None):
        headers = {}
        if self.token:
            headers['token'] = self.token
        if data is not None:
            if type(data) is not str:
                data = json.dumps(data)
            headers['Content-Type'] = 'application/json'
            if method == requests.get:
                method = requests.post

        p = method(
            self.appbase + entrypoint,
            data=data,
            headers=headers,
            auth=auth,
            verify=self.ssl_verify
        )
        response = json.loads(p.text)
        callingfct = inspect.getouterframes(inspect.currentframe(), 2)[1][3]

        if p.status_code not in (200, 201):
            logging.error("phpipam.%s: Failure %s" % (callingfct, p.status_code))
            logging.error(response)
            self.error = p.status_code
            self.error_message = response['message']
            raise requests.exceptions.HTTPError(response=response)

        if not response['success']:
            logging.error("phpipam.%s: FAILURE: %s" % (callingfct, response['code']))
            self.error = response['code']
            raise requests.exceptions.HTTPError(response=response)

        logging.info("phpipam.%s: success %s" % (callingfct, response['success']))
        return response['data']

    # Authentication
    def login(self):
        "Login to phpIPAM and get a token."
        ticketJson = self.__query('/user/', auth=HTTPBasicAuth(self.username, self.password), method=requests.post)
        # Ok So now we have a token!
        self.token = ticketJson['token']
        self.token_expires = ticketJson['expires']
        logging.info("phpipam.login: Sucessful Login to %s" % (self.server))
        logging.debug("phpipam.login: IPAM Ticket expiration: %s" % (self.token_expires))
        return {"expires": self.token_expires}

    def ticket_check(self):
        "check if a ticket is still valid"
        try:
            return self.__query("/user/")
        except Exception:
            return self.login()

    def ticket_extend(self):
        "Extends ticket duration (ticket last for 6h)"
        return self.__query("/user/")

    # Authorization
    def authorization(self, controller):
        "Check the authorization of a controller and get a list of methods"
        return self.__query("/%s/" % (controller))['Network']

    # Sections
    def sections_get_all(self):
        "Get a list of all sections"
        return self.__query("/sections/?links=false")

    def sections_get_id(self, section):
        """Get the ID of a section

        Parameters:
            section: The name of the section you are looking for
        """
        return self.__query("/sections/%s/?links=false" % (section))['id']

    def sections_get(self, section_id):
        """Get the details for a specific section

        Parameters:
            section_id = section identifier. Can be the id number or name.
        """
        return self.__query("/sections/%s/?links=false" % (section_id))

    def sections_get_subnets(self, section_id):
        """Get the subnets for a specific section

         Parameters:
             section_id = section identifier. Can be the id number or name.
         """
        return self.__query("/sections/%s/subnets/?links=false" % (section_id))

    def sections_create(self, section_id, masterSection=0):
        """Create a section

         Parameters:
             section_id = section name.
         """
        data = {'name': section_id}
        if masterSection != 0:
            data['masterSection'] = masterSection
        return self.__query("/sections/", data=data)

    def sections_delete(self, section_id,):
        """Delete a section

        Parameters:
        section_id = section name or id.
        """
        return self.__query("/sections/%s/" % (section_id), method=requests.delete)

    # Subnet
    def subnet_get(self, subnet_id):
        """Get Information about a specific subnet

        Parameters:
        subnet_id: The subnet identifier either the ID or cidr
        """
        return self.__query("/subnets/%s/?links=false" % (subnet_id))

    def subnet_search(self, subnet_id):
        """Search by cidr

        Parameters:
        subnet_id: The subnet cidr
        """
        return self.__query("/subnets/cidr/%s/?links=false" % (subnet_id))

    def subnet_all(self, subnet_id):
        """Get all addresses in a subnet

        Parameters:
        subnet_id: The subnet id
        """
        return self.__query("/subnets/%s/addresses/?links=false" % (subnet_id))

    def subnet_first_available(self, subnet_id, mask):
        """Get first available

        Parameters:
        subnet_id: The subnet id
        """
        return self.__query("/subnets/%s/first_subnet/%s/?links=false" % (subnet_id,mask))


    def subnet_create(self, subnet, mask, sectionId, mastersubnet_id, description, vlanid=None, nameserverid=None):
        """Create new subnet

        Parameters:
        subnet: The subnet
        mask: the subnet mask
        sectionId
        description: description
        vlanid:
        mastersubnet_id:
        nameserverid:"""
        data = {
            'subnet': subnet,
            'mask': mask,
            "sectionId": sectionId,
            'description': description,
            'vlanId': vlanid,
            'mastersubnet_id': mastersubnet_id,
            'nameserverId': nameserverid
        }
        return self.__query("/subnets/", data=data)

    def subnet_nested_create(self, subnet, mask, sectionId, mastersubnet_id, description, vlanid=None, nameserverid=None):
        """Create new subnet

        Parameters:
        subnet: The subnet
        mask: the subnet mask
        sectionId
        description: description
        vlanid:
        mastersubnet_id:
        nameserverid:"""
        data = {
            'subnet': subnet,
            'mask': mask,
            "sectionId": sectionId,
            'description': description,
            'vlanId': vlanid,
            'nameserverId': nameserverid
        }
        return self.__query("/subnets/%s/first_subnet/%s/" % (mastersubnet_id,mask), data=data)

    def subnet_delete(self, subnet_id, ):
        """Delete a subnet

        Parameters:
        subnet_id = subnet name or id.
        """
        return self.__query("/subnets/%s/" % (subnet_id), method=requests.delete)

    # Address
    def address_get(self, address_id):
        """Get Information about a specific address

        Parameters:
        address_id: The address identifier either the ID or cidr
        """
        return self.__query("/addresses/%s/?links=false" % (address_id))

    def address_search(self, address):
        """Search for a specific address

        Parameters:
        address: The address identifier either the ID or address
        """
        return self.__query("/addresses/search/%s/?links=false" % (address))

    def address_update(self, ip, hostname=None, description=None, is_gateway=None, mac=None):
        """Update address informations"""
        orgdata = self.address_search(ip)[0]
        data = {}
        if hostname is not None:
            data["hostname"] = hostname
        if description is not None:
            data["description"] = description
        if is_gateway is not None:
            data["is_gateway"] = is_gateway
        if mac is not None:
            data["mac"] = mac
        return self.__query("/addresses/%s/" % orgdata['id'], method=requests.patch, data=data)

    def address_create(self, ip, subnet_id, hostname, description="", is_gateway=0, mac=""):
        """Create new address

        Parameters:
        number: address number
        name: short name
        description: description"""
        data = {
            "ip": ip,
            "subnetId": subnet_id,
            "hostname": hostname,
            "description": description,
            "is_gateway": is_gateway,
            "mac": mac,
        }
        return self.__query("/addresses/", data=data)

    def address_create_first_free(self, subnet_id, hostname, description="", is_gateway=0, mac=""):
        """Create new address

        Parameters:
        number: address number
        name: short name
        description: description"""
        data = {
            "subnetId": subnet_id,
            "hostname": hostname,
            "description": description
        }
        return self.__query("/addresses/first_free/", data=data)

    # VLAN
    def vlan_get(self, vlan_id):
        """Get Information about a specific vlan

        Parameters:
        vlan_id: The vlan identifier either the ID or cidr
        """
        return self.__query("/vlans/%s/?links=false" % (vlan_id))

    def vlan_get_id(self, vlan_id):
        """vlan_get_id
        search for the ID of a vlan.

        Parameters:
        vlan: The vlan to search for
        """
        return self.__query("/vlans/search/%s/?links=false" % (vlan_id))[0]['id']

    def vlan_subnets(self, vlan_id):
        """Get vlan subnets

        Parameters:
        vlan_id: The vlan identifier
        """
        return self.__query("/vlans/%s/subnets/?links=false" % (vlan_id))

    def vlan_create(self, number, name, description=""):
        """Create new vlan

        Parameters:
        number: vlan number
        name: short name
        description: description
        """
        data = {
            'number': number,
            'name': name,
            'description': description,
        }
        return self.__query("/vlans/", data=data)

    def vlan_delete(self, vlan_id, ):
        """Delete a vlan

        Parameters:
        vlan_id = vlan name or id.
        """
        return self.__query("/vlans/%s/" % (vlan_id))
def get_real_subnets(id):
    subnets = phpipam.sections_get_subnets(id)
    output = [{
        'id': subnet['id'],
        'subnet': subnet['subnet'],
        'mask': subnet['mask'],
        'description': subnet['description'],
        'masterSubnetId': subnet['masterSubnetId'],
        'location': subnet["location"],
        'free_host_percent': subnet["usage"]["freehosts_percent"]
        } for subnet in subnets if subnet['isFolder'] == "0"]
    return output

def cidr_to_netmask(cidr):
    host_bits = 32 - int(cidr)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return netmask

def pull_all_subnet_location(public_subnets): 
###########################################
#Create json lists by Location and add all nested subnets
###########################################
    output = []
    for location in locations:
        print(f"Location now:: {location}....\n")
        location_dict = {}
        location_list = []
        location_name = str(location["name"])
        location_dict["%s" % (location_name)] = {}
        location_file = location_name + ".json"
        for subnet in public_subnets:
            if subnet["location"] == location["id"]:
                location_list.append(subnet)
        ##APPEND LOWER LEVEL SUBNETS THAT DON"T HAVE LOCATION CODE##
        # for subnet in public_subnets:
        #     for record in location_list:
        #         if subnet['masterSubnetId'] == record["id"]:
        #             location_list.append(subnet)
        location_dict["%s" % (location_name)] = location_list
        output.append(location_dict)
        # with open(location_file, 'w') as stream:
        #     stream.write(json.dumps(location_list))
    # print(output)
    return output

def get_public_sectionid_available(location_json, requested_dc, size=29):
    #DEFINE WHICH DC TO SEARCH THROUGH and search through {location} Customers blocks for first available /29
    holder = requested_dc
    if requested_dc == "Akron" or requested_dc == "Independence":
        holder = "AKR_IND" 
    elif requested_dc == "Northpointe" or requested_dc == "Youngstown":
        holder = "YNG_NOR"
    elif requested_dc == "BoiseBlackEagle" or requested_dc == "BoiseVictoryView":
        holder = "Boise"
        requested_dc = "Boise Victory-View"        
    elif requested_dc == "DuluthTechDrive":
        holder = "Duluth" 
        requested_dc = "Duluth"    

    #Set Location IDX
    print("This is holder: "+holder)
    print(f"Global locations: {locations}")
    for idx,location in enumerate(locations):
        print(location["name"])
        if holder == str(location["name"]):
            subset_number = idx    
    print(f"Locations json:: {location_json}\n")
    print(f"Locations for subset nu:  {location_json[subset_number]}\nSubset number:: {subset_number}")
    print(f"Holder:: {holder}")
    for subnet in location_json[subset_number]["%s" % (holder)]:
        print(f"Get public sectionId: {subnet}")   #print(subnet)
        name_holder = subnet["description"]
        expected_string = ("%s Customers" % (requested_dc))
        if expected_string in name_holder:
            try:
                first_avail = phpipam.subnet_first_available(subnet["id"],size)    
                return (first_avail, subnet["id"])
            except:
                print("no /29 available in %s" % (subnet["description"]))
    return("no /29 available in %s" % (holder), None)

def assign_base_values():
    user_arg = None
    pswd_arg = None
    location_arg = None
    description_arg = None
    return user_arg, pswd_arg, location_arg, description_arg

def error_check_values(user_arg,pswd_arg,location_arg,description_arg):
    bad_value = False
    if location_arg is not None:
        location_holder = ""
        location_arg = location_arg.tolower()
        location_arg[0] = location_arg[0].toupper()
    else: 
        print("no location found")
        bad_value = True
    if description_arg is None:
        print("no description given")
        bad_value = True
    return bad_value

def main(user_arg,pswd_arg,location_arg,description_arg,url_arg,appid_arg):
    #bad_check = error_check_values(user_arg, pswd_arg, location_arg, description_arg)
    #if bad_check is True:
    #    print("error checks failed")
    #    return 0
    phpipam_obj = {
            'server': 'https://ipam.involta.com',
            'app_id': 'app',
            'username': 'user',
            'password': 'password'
    }
    global locations
    #AKR_IND split into Akron and Independence
    #YNG_NOR split into Youngstown and Northpointe
    #Commented out for testing
    '''locations = [
        { "name": "Marion", "id": "10" }, 
        { "name": "Duluth", "id": "4" },
        { "name": "AKR_IND", "id": "2" },
        { "name": "Canton", "id": "12" },
        { "name": "Boise", "id": "5" },
        { "name": "Tucson", "id": "6" },
        { "name": "YNG_NOR", "id": "3" }
    ]'''
    locations = [
        { "name": "Marion", "id": "10" }, 
        { "name": "Duluth", "id": "4" },
        { "name": "AKR_IND", "id": "2" },
        { "name": "Canton", "id": "12" },
        { "name": "Boise", "id": "1" },
        { "name": "Tucson", "id": "6" },
        { "name": "YNG_NOR", "id": "3" }
    ]
    #prompt user and password and update phpipam obj
    #user = input('Username: ')
    #pswd = getpass.getpass('Password: ')
    print(url_arg)
    print(appid_arg)
    print(user_arg)
    print(pswd_arg)
    phpipam_obj['server'] = url_arg
    phpipam_obj['app_id'] = appid_arg
    phpipam_obj['username'] = user_arg
    phpipam_obj['password'] = pswd_arg
    location_worker = location_arg
    description_worker = description_arg

    #create global phpipam class object from obj with json values
    global phpipam
    phpipam = phpIPAM(**phpipam_obj, ssl_verify=False)
    phpipam.login()    

###########################################
#Create json lists of full_public_subnets and public_subnets (only the ones with folders)
#save as json files
#find the first available /29 in the subnet with id == 52
###########################################
    all_sections = phpipam.sections_get_all()
    print(f"All Sections:: {all_sections}\n")
    for section in all_sections:
        print(section["name"])
        #Commenting the section name for testing
        if "IPv4 Public" == section["name"]:
        #if "Customers" == section["name"]:     #Revert it back after testing
            public_section_id = section["id"]

    #all subnet info contains non filtered data
    all_subnet_info = phpipam.sections_get_subnets(public_section_id)
    #public_subnets contains all subnets (filtered data points) under the IPv4 Public section
    public_subnets = get_real_subnets(public_section_id)
    print(f"Public subnets:: {public_subnets}\n")
    #location_json contains <location>: {}, <location2>: {}...
    location_json = pull_all_subnet_location(public_subnets)
    available_29_id, top_customer_subnet_id = get_public_sectionid_available(location_json, location_worker)
    print("available 29: "+available_29_id)
    with open('non_filtered.json', 'w') as stream:
        stream.write(json.dumps(all_subnet_info))
    with open('ALL.json', 'w') as stream:
        stream.write(json.dumps(location_json))
    if "no /29 available" not in available_29_id:
        print(f"inside no /29:: {available_29_id}")
        first_avail = available_29_id
        first_avail_id = None
        print("Top customer ID: " + top_customer_subnet_id)
        print("First Available /29: " + first_avail)
        subnet_test = first_avail.split("/")[0]
        mask_test = first_avail.split("/")[1]
        cidr_test = cidr_to_netmask(mask_test)
        phpipam.subnet_nested_create(subnet_test, mask_test, public_section_id, top_customer_subnet_id, description_worker)
        new_subnet_info = get_real_subnets(public_section_id)
        for subnet in new_subnet_info:
            subnet_mask = subnet["subnet"] + "/" + subnet["mask"]
            if first_avail == subnet_mask:
                first_avail_id = subnet["id"]
        if first_avail_id is not None:
            vip_gateway = phpipam.address_create_first_free(first_avail_id, hostname=location_worker, description="VIP Gateway")
            vrrp_1 = phpipam.address_create_first_free(first_avail_id, hostname=location_worker , description="VRRP #1")
            vrrp_2 = phpipam.address_create_first_free(first_avail_id, hostname=location_worker, description="VRRP #2")
            palo_ip = phpipam.address_create_first_free(first_avail_id, hostname=location_worker, description="VPALO")
            customer_first = phpipam.address_create_first_free(first_avail_id, hostname="", description="Customer")
            create = True
            while create is True:
                try:
                    customer_last = phpipam.address_create_first_free(first_avail_id, hostname="", description="Customer")
                except:
                    create = False
            
            print("VIP=" + vip_gateway)
            print("vrrp1=" + vrrp_1)
            print("vrrp2=" + vrrp_2)
            print("palo_ip=" + palo_ip)
            print("customer_first=" + customer_first)
            print("customer_last=" + customer_last)
            print("cidr=" + cidr_test)
            print("mask=" + mask_test)
        else:
            print("Failed to get first available id")
    return ("firstAvail:"+first_avail, "vipGateway:"+vip_gateway, "vrrp1:"+vrrp_1, "vrrp2:"+vrrp_2, "paloIP:"+palo_ip, "custFirst:"+customer_first, "custLast:"+customer_last, "cidr:"+cidr_test, "mask:"+mask_test)

if __name__ == '__main__':
    #main("admin","Elastic+123","Boise","testDesc","https://172.16.22.168/phpipam","test")
    main(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5],sys.argv[6])
