    def check_disk_encryption_gcp(self,**kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                for zone in zones:
                    try:
                        request = compute.disks().list(project=project_id, zone=zone).execute()
                        if request.get('items'):
                            while True:
                                total_results = request['items']
                                for each_resource in total_results:
                                    evaluated_resources += 1
                                    if not each_resource.get('diskEncryptionKey'):
                                        output.append(OrderedDict(ResourceId=each_resource.get('id'),
                                                                  ResourceName=each_resource.get('name'),
                                                                  ResourceType='Compute_Engine'))
                                if request.get("nextPageToken", ""):
                                    request = compute.disks().list(project=project_id, zone=zone,
                                                                   pageToken=request.get("nextPageToken", "")).execute()
                                else:
                                    break
                    except Exception as e:
                        if "Invalid JWT Signature." in str(e):
                            continue
                        else:
                            raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))
