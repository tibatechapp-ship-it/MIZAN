from transformers import pipeline

pipe = pipeline("text-generation", trust_remote_code=True)
