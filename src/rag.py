# %%
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain.tools.retriever import create_retriever_tool
from file_tools import module_dict
import os

print(f"{os.getenv('GOOGLE_API_KEY')[:5]}...")
embeddings = GoogleGenerativeAIEmbeddings(model="models/text-embedding-004", google_api_key=os.getenv("GOOGLE_API_KEY", ""))
# embeddings = openai_embeddings = OpenAIEmbeddings(
#     model="gemini-embedding-exp-03-07",
#     api_key=os.getenv("GEMINI_API_KEY", ""),
#     base_url="https://chatbox.isrc.ac.cn/api"
# )

# %%
DOC_STORAGE_PATH = "../storage/docs_store"
if os.path.exists(DOC_STORAGE_PATH):
    doc_store = Chroma(persist_directory=DOC_STORAGE_PATH, embedding_function=embeddings)
else:
    from langchain_community.document_loaders import DirectoryLoader
    loader = DirectoryLoader('../doc_files/', glob="**/*.md", show_progress=True)
    docs = loader.load()
    docs = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200, add_start_index=True).split_documents(docs)
    print(f"Loaded and split {len(docs)} other documents.")
    doc_store = Chroma.from_documents(
        docs,
        embedding=embeddings,
        persist_directory=DOC_STORAGE_PATH
    )


# %%
# 加入CWE数据
CWE_STORAGE_PATH = "../storage/cwe_store"
if os.path.exists(CWE_STORAGE_PATH):
    cwe_store = Chroma(persist_directory=CWE_STORAGE_PATH, embedding_function=embeddings)
else:
    from langchain_community.document_loaders.csv_loader import CSVLoader
    cwe_data = CSVLoader(
        file_path='../data/1194.csv',
        csv_args={'delimiter': ',', 'quotechar': '"'},
    ).load()
    cwe_data = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200, add_start_index=True).split_documents(cwe_data)
    print(f"Loaded and split {len(cwe_data)} CWE documents.")
    cwe_store = Chroma.from_documents(
        cwe_data,
        embedding=embeddings,
        persist_directory=CWE_STORAGE_PATH
    )
    
# %%
doc_retriver = doc_store.as_retriever()
cwe_retriver = cwe_store.as_retriever()


doc_retriver = create_retriever_tool(
    doc_retriver,
    name="doc_retriver",
    description="useful for when you need to find information about opentitan components, such as their functionality, design, or implementation details and security info. The input to this tool should be a component name or a brief description of the component, or information that you want to find in the opentitan repository, such as 'spi_device' or 'uart'."
)
cwe_retriver_tool = create_retriever_tool(
    cwe_retriver,
    name="cwe_retriver",
    description="useful for when you need to find information about a specific Common Weakness Enumeration (CWE) identifier, such as its description, potential impacts, or mitigation strategies. The input to this tool should be a CWE identifier like 'CWE-79' or a brief description of the weakness."
)
print("RAG retriver tools are ready to use.")
# docs = doc_store.similarity_search("hmac模块的功能介绍")
# print(f"找到 {len(docs)} 个相关文档")
# print(docs)
    
    
    
    # %%
