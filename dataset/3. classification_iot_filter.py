import pandas as pd

# Read with header row, and don't force dtype (let pandas infer)
df = pd.read_csv("bert_class_results.csv")

# Check the name of the third column (you can print df.columns if unsure)
# For example, let's say it's called 'is_iot'
df_filtered = df[df['is_iot'] == 1]

# Save the result
df_filtered.to_csv("bert_iot_filtered.csv", index=False)
