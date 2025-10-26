import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Membaca dataset
df = pd.read_csv("dataset.csv")

plt.figure(figsize=(12, 6))
top_attackers = df['fields_source_address'].value_counts().head(10)  # Ambil 10 IP paling sering menyerang
sns.barplot(x=top_attackers.index, y=top_attackers.values, palette="Reds")
plt.xticks(rotation=45)
plt.title("Top 10 IP Penyerang")
plt.xlabel("IP Penyerang")
plt.ylabel("Jumlah Serangan")
plt.show()