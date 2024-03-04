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



        #deletes all documents in specified index
        def delete_all_docs(self):
            try:
                self.es.delete_by_query(index=self.index_name, body={"query": {"match_all": {}}})
                print("[+]Documents deleted sucessfully!!!")
            except Exception as e:
                print(e)
                print("[+]Unable delete documents")



        #deletes document from index
        def delete_document(self, client_id):
            try:
                self.es.delete(index=self.index_name, id=client_id)
                print("[+]Document deleted sucessfully!!! \n")
            except:
                print("[-]Document does not exist!!! \n")



        #tabulate es date using prettytable
        def tabulate_index_data(self, resp):
            for hit in resp:
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



        def retrieve_client_information(self):
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "ip"}},
                            {"exists": {"field": "system"}},
                            {"exists": {"field": "node"}},
                            {"exists": {"field": "release"}},
                            {"exists": {"field": "version"}},
                            {"exists": {"field": "machine"}},
                            {"exists": {"field": "date_today"}},
                            {"exists": {"field": "time_now"}}
                        ]
                    }
                }
            }

            try:
                response = self.es.search(index=self.index_name, body=query, size=10)
                hits = response['hits']['hits']
                if hits:
                    self.tabulate_index_data(hits)
                else:
                    print("No documents found with the specified fields.")
            except Exception as e:
                print(f"An error occurred: {e}")




        def index_capture(self, capture):
            try:
                response = self.es.count(index=self.index_name)
                num_documents = response['count']
                print(f"Doc ID: {num_documents}")
                document_id = num_documents + 1 
                self.es.index(index=self.index_name, id=document_id, body=capture)

                print(f"Capture data saved to Elasticsearch with document ID: {document_id}")
                self.es.indices.refresh(index=self.index_name)


            except Exception as e:
                print(f"Error occurred while saving capture to Elasticsearch: {e}")

