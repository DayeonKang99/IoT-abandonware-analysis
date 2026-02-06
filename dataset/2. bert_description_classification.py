import torch
import csv
from transformers import BertTokenizer, BertForSequenceClassification
import operator
from concurrent.futures import ThreadPoolExecutor
import os

# Function to load the pre-trained model and tokenizer
def load_model_and_tokenizer(model_path='iotspotter_epoch-4.model'):
    print("Loading tokenizer...")
    tokenizer = BertTokenizer.from_pretrained('bert-base-uncased', do_lower_case=True)
    
    print("Loading model...")
    model = BertForSequenceClassification.from_pretrained("bert-base-uncased", num_labels=2, output_attentions=False, output_hidden_states=False)
    
    print("Loading state dict...")
    model.load_state_dict(torch.load(model_path, map_location=torch.device('cpu')))
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model.to(device)
    
    print("Model and tokenizer loaded successfully!")
    return model, tokenizer, device

# Function to encode the text into input format for BERT
def encode_text(text, tokenizer, device):
    encoded_text = tokenizer.batch_encode_plus(
        [text],
        add_special_tokens=True,
        return_attention_mask=True,
        pad_to_max_length=True,
        max_length=512,
        truncation=True,
        return_tensors='pt'
    )
    input_ids = encoded_text['input_ids'].to(device)
    attention_mask = encoded_text['attention_mask'].to(device)
    return input_ids, attention_mask

# Function to predict whether a description is IoT or not
def predict_description(description, model, tokenizer, device):
    input_ids, attention_mask = encode_text(description, tokenizer, device)
    
    inputs = {'input_ids': input_ids, 'attention_mask': attention_mask}
    
    with torch.no_grad():
        probabilities = model(**inputs)

    logits = probabilities[0].detach().cpu().numpy()
    result_probs = dict(zip(['non_iot', 'iot'], logits[0]))
    result = max(result_probs.items(), key=operator.itemgetter(1))[0]
    
    return 1 if result == 'iot' else 0  # IoT = 1, Non-IoT = 0

# Function to process each row and return classification results
def process_row(row, model, tokenizer, device):
    sha256, package_name, description = row
    print("Processing: ", package_name)
    classification = predict_description(description, model, tokenizer, device)
    return sha256, package_name, classification

# Function to classify descriptions from description.csv and save results in iot_check.csv
def classify_and_save(input_csv='descriptions.csv', output_csv='bert_class_results.csv', num_threads=200):
    model, tokenizer, device = load_model_and_tokenizer()
    
    results = []
    
    # Read the CSV file
    with open(input_csv, 'r', newline='', encoding='utf-8') as infile:
        reader = csv.reader(infile)
        next(reader)  # Skip header
        
        rows = list(reader)  # Convert to list for multithreading
    
    with open(output_csv, 'a', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        file_empty = os.stat(output_csv).st_size == 0  # Check if file is empty to write header
        if file_empty:

            writer.writerow(['sha256', 'package_name', 'is_iot'])  # Write header

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            results = list(executor.map(lambda row: process_row(row, model, tokenizer, device), rows))
        
            for sha256, package_name, classification in results:
                writer.writerow([sha256, package_name, classification])
    
    print(f"Classification results saved to {output_csv}")

# Run the function
if __name__ == "__main__":
    classify_and_save()
