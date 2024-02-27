import json
from prettytable import PrettyTable
from elasticsearch import Elasticsearch



class EsHandler:


        def __init__(self, index_name, es_url):
            self.pt = PrettyTable()
            self.index_name = index_name
            self.es = Elasticsearch(es_url)



        #store client info in elastic search
        def store_client_information(self, client_info, document_id=0):
            try:
                print(client_info)
                if self.es.exists(index=self.index_name, id=document_id):
                    self.es.update(index=self.index_name, id=document_id, body={"doc": client_info})
                    print("[+] Document Updated!!!")
                else:
                    resp = self.es.index(index=self.index_name, id=document_id, body=client_info)
                    print("information stored sucesfully")
            except Exception as e:
                print("[+]Unable to store data!!!")
                print(e)



        #deletes document from index
        def delete_document(self, client_id):
            try:
                self.es.delete(index=self.index_name, id=client_id)
                print("[+]Document deleted sucessfully!!! \n")
            except:
                print("[-]Document does not exist!!! \n")



        #tabulate es date using prettytable
        def tabulate_index_data(self, resp):
            for hit in resp['hits']['hits']:
                self.pt.field_names = ["Client-ID", "IP-Address", "System", "Node", "Release", "Version", "Machine", "Date-Joined", "Time-Joined"]
                self.pt.add_row([
                             hit["_id"],
                             hit["_source"].get("ip"),
                             hit["_source"].get("system"),
                             hit["_source"].get("node"),
                             hit["_source"].get("release"),
                             hit["_source"].get("version"),
                             hit["_source"].get("machine"),
                             hit["_source"].get("date_today"),
                             hit["_source"].get("time_now"),
                             ])

            print(self.pt)
            self.pt.clear()



        #retrieve client information documents from elastic search
        def retrieve_client_information(self):
            try:
                resp = self.es.search(index=self.index_name, size=100, query={"match_all": {}})
                self.tabulate_index_data(resp)
            except Exception as e:
                print(e)


